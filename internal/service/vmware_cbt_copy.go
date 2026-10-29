package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"vdxclone/internal/nbd"
	"vdxclone/internal/vmware"
)

// The data path of a CBT warm import: the changed (or, for the base copy,
// allocated) areas of each source disk are read from nbdkit's VDDK plugin over
// NBD at a snapshot, and written at the same offsets into a sparse raw staging
// file on this host. See docs/CBT-IMPORT.md.

const (
	// cbtReadConns is how many parallel NBD connections read one disk (each is
	// its own VDDK handle). One synchronous connection leaves most of the link
	// idle; a handful keeps it busy without exhausting ESXi's NFC slots.
	cbtReadConns = 4
	// cbtChunk is the unit of work: one NBD read + one pwrite.
	cbtChunk = 4 << 20
)

// cbtCopyExtents copies each area from the source into dst at the same offset,
// spreading chunks over the readers (one goroutine per reader — an nbd.Client
// is not safe for concurrent use). fresh=true is the base copy into a new
// sparse file: all-zero chunks are skipped, they are already holes. A delta
// (fresh=false) must overwrite stale data, so zero chunks are punched (or
// written as zeroes where punching isn't supported). onBytes reports progress.
// Areas outside dst's size are refused, never written.
func cbtCopyExtents(ctx context.Context, readers []io.ReaderAt, dst *os.File, areas []vmware.ChangedArea, fresh bool, onBytes func(int64)) error {
	if len(readers) == 0 {
		return fmt.Errorf("no source readers")
	}
	fi, err := dst.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	type chunk struct{ off, n int64 }
	var chunks []chunk
	for _, a := range areas {
		if a.Start < 0 || a.Length < 0 || a.Start+a.Length > size {
			return fmt.Errorf("changed area [%d,+%d) lies outside the %d-byte disk", a.Start, a.Length, size)
		}
		for off := a.Start; off < a.Start+a.Length; off += cbtChunk {
			n := a.Start + a.Length - off
			if n > cbtChunk {
				n = cbtChunk
			}
			chunks = append(chunks, chunk{off, n})
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan chunk)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	setErr := func(err error) {
		errOnce.Do(func() { firstErr = err; cancel() })
	}
	zero := make([]byte, cbtChunk)
	for _, r := range readers {
		wg.Add(1)
		go func(r io.ReaderAt) {
			defer wg.Done()
			buf := make([]byte, cbtChunk)
			for c := range work {
				b := buf[:c.n]
				if _, err := r.ReadAt(b, c.off); err != nil {
					setErr(fmt.Errorf("read source at %d (+%d): %w", c.off, c.n, err))
					return
				}
				if bytes.Equal(b, zero[:c.n]) {
					if !fresh {
						if err := punchOrZero(dst, zero[:c.n], c.off); err != nil {
							setErr(err)
							return
						}
					}
				} else if _, err := dst.WriteAt(b, c.off); err != nil {
					setErr(fmt.Errorf("write staging at %d: %w", c.off, err))
					return
				}
				if onBytes != nil {
					onBytes(c.n)
				}
			}
		}(r)
	}
feed:
	for _, c := range chunks {
		select {
		case work <- c:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// punchOrZero turns [off, off+len(zero)) of f into zeroes: a hole where the
// filesystem can punch one (keeps the staging file sparse), else written zeroes.
func punchOrZero(f *os.File, zero []byte, off int64) error {
	const keepSize, punchHole = 0x01, 0x02 // FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
	if syscall.Fallocate(int(f.Fd()), keepSize|punchHole, off, int64(len(zero))) == nil {
		return nil
	}
	if _, err := f.WriteAt(zero, off); err != nil {
		return fmt.Errorf("zero staging at %d: %w", off, err)
	}
	return nil
}

// vddkServer is what the production disk opener needs from the vSphere client.
type vddkServer interface {
	ServeVDDKDisk(ctx context.Context, d vmware.VDDKDisk) (*vmware.NBDServer, error)
}

// cbtDisk is one opened source disk: parallel readers, an abort that unblocks
// reads in flight (stops the server), and a close that releases everything.
type cbtDisk struct {
	readers []io.ReaderAt
	abort   func()
	close   func()
}

// cbtOpenVDDK serves one source disk at a snapshot through nbdkit's VDDK plugin
// (read-only, private unix socket) and opens cbtReadConns NBD connections to
// it. close drops the connections and stops nbdkit — which must happen before
// the snapshot is removed (nbdkit holds its disk open).
func (s *Service) cbtOpenVDDK(ctx context.Context, src cbtSource, r *cbtImport, pass string, disk vmware.CBTDisk, snap string) (*cbtDisk, error) {
	vs, ok := src.(vddkServer)
	if !ok {
		return nil, fmt.Errorf("this vSphere connection can't serve disks through VDDK")
	}
	srv, err := vs.ServeVDDKDisk(ctx, vmware.VDDKDisk{
		LibDir: s.VDDKLibDir(), User: r.User, Pass: pass, MOID: r.MOID, File: disk.FileName, Snapshot: snap,
	})
	if err != nil {
		return nil, err
	}
	return dialNBDReaders(srv, cbtReadConns, disk.Capacity)
}

// dialNBDReaders opens n NBD connections to an nbdkit server and checks the
// export is the size vSphere reported (a mismatch means the wrong file).
// abort stops nbdkit only — its sockets then EOF, failing any read in flight —
// so the clients are closed (close) only once no goroutine uses them.
func dialNBDReaders(srv *vmware.NBDServer, n int, capacity int64) (*cbtDisk, error) {
	var conns []*nbd.Client
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			for _, c := range conns {
				_ = c.Close()
			}
			_ = srv.Close()
		})
	}
	for i := 0; i < n; i++ {
		c, err := nbd.Dial(srv.Addr(), "")
		if err != nil {
			msg := srv.Stderr()
			closeAll()
			return nil, fmt.Errorf("open the source disk over NBD: %v %s", err, msg)
		}
		conns = append(conns, c)
		if capacity > 0 && int64(c.Size()) != capacity {
			closeAll()
			return nil, fmt.Errorf("the served disk is %d bytes but vSphere reports %d", c.Size(), capacity)
		}
	}
	d := &cbtDisk{close: closeAll, abort: func() { _ = srv.Close() }}
	for _, c := range conns {
		d.readers = append(d.readers, c)
	}
	return d, nil
}
