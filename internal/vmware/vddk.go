package vmware

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"crypto/tls"

	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// VDDKAvailable reports whether nbdkit and its VDDK plugin are installed. The
// VDDK library itself is proprietary (VMware/Broadcom, not redistributable) and
// is supplied by the operator via a libdir — this only checks the apt-installable
// wrapper, so the UI can show/hide the "fastest" transport option accordingly.
func VDDKAvailable() bool {
	if _, err := exec.LookPath("nbdkit"); err != nil {
		return false
	}
	for _, g := range []string{
		"/usr/lib/*/nbdkit/plugins/nbdkit-vddk-plugin.so",
		"/usr/lib/nbdkit/plugins/nbdkit-vddk-plugin.so",
	} {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			return true
		}
	}
	return false
}

// ExportVMVDDK reads a powered-off VM's disks through VMware VDDK over NBD (served
// by nbdkit, read-only) and converts each straight to a local raw file with
// qemu-img. VDDK reads only ALLOCATED blocks and uses async I/O, so for sparse/
// large disks it is the best wall-clock transport. It is strictly READ-ONLY on the
// source (nbdkit opens the disk read-only; nothing is powered, snapshotted, or
// reconfigured) and, like the datastore transport, requires the source powered OFF
// and without snapshots — VDDK *could* read a running VM via a snapshot, but our
// hard rule forbids snapshotting the source, so we stay cold-only.
//
// The VDDK library is proprietary and operator-supplied: libdir must point at an
// unpacked VMware-vix-disklib tree. Returns local raw-disk paths in device order.
func (c *Client) ExportVMVDDK(ctx context.Context, moid, destDir, libdir, user, pass string, logf func(string, ...any), prog func(ExportProgress)) ([]string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !VDDKAvailable() {
		return nil, fmt.Errorf("the VDDK transport needs nbdkit + its VDDK plugin (apt install nbdkit nbdkit-plugin-vddk) — not installed")
	}
	if strings.TrimSpace(libdir) == "" {
		return nil, fmt.Errorf("the VDDK library path is not set — download VMware VDDK (proprietary, can't be bundled) and set its libdir on the Storage page")
	}
	ref := types.ManagedObjectReference{Type: "VirtualMachine", Value: moid}
	var vm mo.VirtualMachine
	pc := property.DefaultCollector(c.gc.Client)
	if err := pc.RetrieveOne(ctx, ref, []string{"config.hardware", "runtime.powerState", "snapshot"}, &vm); err != nil {
		return nil, fmt.Errorf("read VM layout: %w", err)
	}
	if vm.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOff {
		return nil, fmt.Errorf("the VDDK transport requires the source powered OFF (it is %s)", vm.Runtime.PowerState)
	}
	if vm.Snapshot != nil && len(vm.Snapshot.RootSnapshotList) > 0 {
		return nil, fmt.Errorf("the VDDK transport is used cold here and can't run against a VM with snapshots — remove them on the source, or use the NFC transport")
	}
	disks, err := flatDisksOf(&vm)
	if err != nil {
		return nil, err
	}

	host := c.gc.Client.URL().Hostname()
	tp, err := tlsThumbprint(host)
	if err != nil {
		return nil, fmt.Errorf("get %s SSL thumbprint for VDDK: %w", host, err)
	}
	// Password via a 0600 file (nbdkit password=+FILE), never on the argv.
	pf, err := os.CreateTemp(destDir, ".vddkpass-")
	if err != nil {
		return nil, err
	}
	pfName := pf.Name()
	_ = pf.Chmod(0o600)
	_, _ = pf.WriteString(pass)
	_ = pf.Close()
	defer os.Remove(pfName)

	var nominalBytes int64
	for _, d := range disks {
		nominalBytes += d.capBytes
	}

	var files []string
	cleanup := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	var completedBytes int64
	for i, d := range disks {
		local := filepath.Join(destDir, "."+sanitizeName(fmt.Sprintf("vddk-disk%d.raw", i)))
		_ = os.Remove(local)
		logf("VDDK: serving %q (%s) via nbdkit → qemu-img convert → %s", d.label, d.fileName, filepath.Base(local))
		runCmd := "exec qemu-img convert -f raw -m 8 -W \"$uri\" -O raw " + shellSingleQuote(local)
		args := []string{
			"-r", "--exit-with-parent", "-U", "-",
			"vddk",
			"libdir=" + libdir,
			"server=" + host,
			"user=" + user,
			"password=+" + pfName,
			"thumbprint=" + tp,
			"vm=moref=" + moid,
			"file=" + d.fileName,
			"transports=nbd:nbdssl",
			"--run", runCmd,
		}
		cmd := exec.CommandContext(ctx, "nbdkit", args...)
		diskStart := time.Now()
		var stderr strings.Builder
		cmd.Stderr = &stderr
		errCh := make(chan error, 1)
		go func() { errCh <- cmd.Run() }()
		tick := time.NewTicker(time.Second)
		lastBytes, lastT := completedBytes, time.Now()
		var derr error
	poll:
		for {
			select {
			case derr = <-errCh:
				break poll
			case now := <-tick.C:
				// qemu-img convert -O raw creates the output at full virtual size
				// up front (sparse) and fills in real blocks, so the apparent
				// st.Size() is pinned at the disk's capacity from the first second
				// and never moves. Measure ALLOCATED blocks instead for true
				// progress and a real rate.
				cur := completedBytes + allocatedBytes(local)
				if prog != nil {
					dt := now.Sub(lastT).Seconds()
					var bps int64
					if dt > 0 {
						bps = int64(float64(cur-lastBytes) / dt)
					}
					prog(ExportProgress{DoneBytes: cur, NominalBytes: nominalBytes, BytesPerSec: bps})
					lastBytes, lastT = cur, now
				}
			}
		}
		tick.Stop()
		if derr != nil {
			_ = os.Remove(local)
			cleanup()
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 400 {
				msg = msg[len(msg)-400:]
			}
			logf("VDDK transfer of %q FAILED after %s: %v: %s", d.label, time.Since(diskStart).Round(time.Second), derr, msg)
			return nil, fmt.Errorf("vddk/nbdkit %s: %v: %s", d.label, derr, msg)
		}
		wrote := allocatedBytes(local) // allocated, not the sparse full-size apparent length
		completedBytes += wrote
		elapsed := time.Since(diskStart)
		var avg int64
		if sec := elapsed.Seconds(); sec > 0 {
			avg = int64(float64(wrote) / sec)
		}
		logf("VDDK: %q done — %d MiB in %s (avg %d MiB/s, allocated-blocks only)", d.label, wrote/(1<<20), elapsed.Round(time.Second), avg/(1<<20))
		files = append(files, local)
		if prog != nil {
			prog(ExportProgress{DoneBytes: completedBytes, NominalBytes: nominalBytes})
		}
	}
	logf("VDDK export finished: %d disk file(s), %d MiB total", len(files), completedBytes/(1<<20))
	return files, nil
}

// tlsThumbprint returns the SHA-1 thumbprint (AA:BB:…) of the leaf certificate
// presented by host:443, which nbdkit's VDDK plugin needs to connect.
func tlsThumbprint(host string) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
		net.JoinHostPort(host, "443"), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // thumbprint only
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no peer certificate from %s", host)
	}
	sum := sha1.Sum(certs[0].Raw)
	var b strings.Builder
	for i, x := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String(), nil
}

// allocatedBytes returns the number of bytes actually allocated on disk for the
// file at path (st_blocks × 512), i.e. excluding holes in a sparse file. This is
// the right progress measure for a raw image qemu-img creates at full virtual
// size up front: its apparent length (st.Size) is the capacity from the start,
// while the allocated size tracks the real data as it is written. Falls back to
// the apparent size if the syscall stat is unavailable, and to 0 if the file is
// not there yet.
func allocatedBytes(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}

// shellSingleQuote wraps s in single quotes for safe use inside nbdkit's --run
// shell string.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// NBDServer is one nbdkit process serving a disk READ-ONLY on a private unix
// socket, for vdxd's own NBD client (internal/nbd) to read from. Close stops it
// and removes its directory (and with it the password file).
type NBDServer struct {
	cmd    *exec.Cmd
	dir    string
	sock   string
	done   chan struct{}
	err    error // nbdkit's exit status, valid once done is closed
	stderr *lockedBuf
}

// Addr is the nbd.Dial address of the server ("unix:/path").
func (s *NBDServer) Addr() string { return "unix:" + s.sock }

// Close stops nbdkit (it holds the VDDK disk handle, which must be released
// before the snapshot it reads can be removed) and removes its directory.
func (s *NBDServer) Close() error {
	if s == nil {
		return nil
	}
	select {
	case <-s.done:
	default:
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-s.done:
		case <-time.After(30 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	}
	return os.RemoveAll(s.dir)
}

// startNBDKit runs `nbdkit -r -f --exit-with-parent -U <sock> <plugin args>` in
// a fresh private directory and waits for the socket. -r: the export is
// read-only whatever the plugin; --exit-with-parent: a vdxd crash never leaves
// an nbdkit holding a source disk open. setup may drop files (a password file)
// into the directory before nbdkit starts, and returns the plugin arguments.
func startNBDKit(ctx context.Context, setup func(dir string) ([]string, error)) (*NBDServer, error) {
	dir, err := os.MkdirTemp("", "vdxnbd-")
	if err != nil {
		return nil, err
	}
	pluginArgs, err := setup(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	sock := filepath.Join(dir, "nbd.sock")
	args := append([]string{"-r", "-f", "--exit-with-parent", "-U", sock}, pluginArgs...)
	s := &NBDServer{cmd: exec.Command("nbdkit", args...), dir: dir, sock: sock, done: make(chan struct{}), stderr: &lockedBuf{}}
	s.cmd.Stderr = s.stderr
	if err := s.cmd.Start(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("start nbdkit: %w", err)
	}
	go func() { s.err = s.cmd.Wait(); close(s.done) }()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			return s, nil
		}
		select {
		case <-s.done:
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("nbdkit exited before serving: %v: %s", s.err, s.stderr.tail(400))
		case <-ctx.Done():
			_ = s.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = s.Close()
			return nil, fmt.Errorf("nbdkit did not open its socket within 60s: %s", s.stderr.tail(400))
		}
	}
}

// Stderr returns the tail of nbdkit's diagnostics (for an error message).
func (s *NBDServer) Stderr() string { return s.stderr.tail(400) }

// VDDKDisk names one disk to serve through VDDK: the VM, the disk file as the
// snapshot froze it, and the snapshot to read it at.
type VDDKDisk struct {
	LibDir   string
	User     string
	Pass     string
	MOID     string
	File     string // "[ds] dir/disk.vmdk"
	Snapshot string // snapshot moref, e.g. "snapshot-123"
}

// ServeVDDKDisk starts nbdkit's VDDK plugin READ-ONLY for one disk on a private
// unix socket. Reading a snapshot of a running VM is consistent: the snapshot's
// disk file is frozen while the VM writes to the delta created above it.
func (c *Client) ServeVDDKDisk(ctx context.Context, d VDDKDisk) (*NBDServer, error) {
	if !VDDKAvailable() {
		return nil, fmt.Errorf("the VDDK transport needs nbdkit + its VDDK plugin — not installed")
	}
	if strings.TrimSpace(d.LibDir) == "" {
		return nil, fmt.Errorf("the VDDK library path is not set")
	}
	if d.Snapshot == "" {
		return nil, fmt.Errorf("a warm-migration read needs a snapshot")
	}
	host := c.gc.Client.URL().Hostname()
	tp, err := tlsThumbprint(host)
	if err != nil {
		return nil, fmt.Errorf("get %s SSL thumbprint for VDDK: %w", host, err)
	}
	return startNBDKit(ctx, func(dir string) ([]string, error) {
		// Password via a 0600 file (password=+FILE), never on the argv.
		pf := filepath.Join(dir, "pass")
		if err := os.WriteFile(pf, []byte(d.Pass), 0o600); err != nil {
			return nil, err
		}
		return []string{
			"vddk",
			"libdir=" + d.LibDir,
			"server=" + host,
			"user=" + d.User,
			"password=+" + pf,
			"thumbprint=" + tp,
			"vm=moref=" + d.MOID,
			"snapshot=" + d.Snapshot,
			"file=" + d.File,
			"transports=nbd:nbdssl",
		}, nil
	})
}

// ServeFile serves a local image READ-ONLY through nbdkit's file plugin. It
// exists so the nbdkit + NBD-client read path can be exercised on a host
// against a scratch image, without a vCenter.
func ServeFile(ctx context.Context, path string) (*NBDServer, error) {
	return startNBDKit(ctx, func(string) ([]string, error) { return []string{"file", "file=" + path}, nil })
}

// lockedBuf collects a child's stderr (capped) for error messages.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *lockedBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.b.Len() < 64<<10 {
		w.b.Write(p)
	}
	return len(p), nil
}

func (w *lockedBuf) tail(n int) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := strings.TrimSpace(w.b.String())
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}
