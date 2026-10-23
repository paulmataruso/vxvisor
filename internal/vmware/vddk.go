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
