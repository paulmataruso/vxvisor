package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// swtpm (software TPM) support. A Windows 11 guest — and increasingly Windows 10
// — expects a TPM 2.0 device. We run one swtpm process per VM, exposing a control
// socket that QEMU attaches as a tpm-crb device. The TPM's NVRAM lives in a
// per-VM state directory that MUST persist across restarts (it holds BitLocker
// keys, SB state, etc.), so it is never cleaned on stop — only on purge.
//
// Lifecycle rules (fail-safe):
//   - swtpm must be up BEFORE QEMU, which connects to the socket at launch.
//   - swtpm runs under the same RunAs uid/gid as QEMU so the dropped-privilege
//     QEMU can open the socket, and so an orphaned swtpm can't run as root.
//   - it is tracked by a pidfile and reaped on Stop/Purge; a stale one from a
//     previous launch is killed first so sockets bind cleanly.

// tpmStateDir holds a VM's swtpm NVRAM + control socket. It lives under
// /var/lib/swtpm/<id> because the distro's AppArmor profile for /usr/bin/swtpm
// only permits socket/state files under a fixed set of paths (notably
// `owner /var/lib/swtpm/** rwk`); putting them in our DiskDir is DENIED by
// AppArmor ("mknod ... denied"). /var/lib/swtpm persists across reboots, which
// the NVRAM requires.
func (m *Manager) tpmStateDir(id string) string {
	return filepath.Join("/var/lib/swtpm", id)
}
func (m *Manager) tpmSock(id string) string  { return filepath.Join(m.tpmStateDir(id), "swtpm-sock") }
func (m *Manager) tpmPidFile(id string) string { return filepath.Join(m.tpmStateDir(id), "swtpm.pid") }

// startSwtpm launches (or relaunches) the per-VM swtpm and returns its control
// socket path. Idempotent: any previous instance for this VM is reaped first.
func (m *Manager) startSwtpm(id string) (string, error) {
	if _, err := exec.LookPath("swtpm"); err != nil {
		return "", fmt.Errorf("swtpm not installed on this host")
	}
	m.stopSwtpm(id) // kill any stale instance holding the socket
	// Parent must be traversable by the RunAs user (MkdirAll would otherwise
	// create it 0750 root). The per-VM dir is 0750 and chowned to RunAs below.
	_ = os.MkdirAll("/var/lib/swtpm", 0o755)
	_ = os.Chmod("/var/lib/swtpm", 0o755)
	dir := m.tpmStateDir(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	sock := m.tpmSock(id)
	_ = os.Remove(sock)

	args := []string{"socket", "--tpm2",
		"--tpmstate", "dir=" + dir,
		"--ctrl", "type=unixio,path=" + sock,
		"--pid", "file=" + m.tpmPidFile(id),
		"--daemon"}
	cmd := exec.Command("swtpm", args...)
	// Run swtpm under the VM RunAs identity (so the socket is owned by the same
	// user QEMU drops to). Also hand it the state dir.
	if m.cfg.VM.RunAs != "" {
		if uid, gid, groups, ok := lookupUser(m.cfg.VM.RunAs); ok {
			_ = chownTree(dir, int(uid), int(gid))
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
				Uid: uid, Gid: gid, Groups: groups,
			}}
		}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("launch swtpm: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// --daemon forks and exits once the control socket is ready; confirm it bound.
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(sock); err == nil {
			return sock, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return "", fmt.Errorf("swtpm socket %s did not appear", sock)
}

// stopSwtpm terminates the VM's swtpm (best effort). The state dir is preserved.
func (m *Manager) stopSwtpm(id string) {
	b, err := os.ReadFile(m.tpmPidFile(id))
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	}
	_ = os.Remove(m.tpmPidFile(id))
	_ = os.Remove(m.tpmSock(id))
}

// chownTree recursively chowns a directory (best effort) so the RunAs swtpm can
// read/write its NVRAM state.
func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		_ = os.Chown(p, uid, gid)
		return nil
	})
}
