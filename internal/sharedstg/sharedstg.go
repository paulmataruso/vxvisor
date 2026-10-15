// Package sharedstg mounts and manages network/shared storage backends from the
// UI: NFS, CIFS, CephFS, and iSCSI sessions. All operations shell out to the
// host tools (mount, umount, iscsiadm). The service layer gates on admin and
// enforces that every backend rides the dedicated storage interface.
package sharedstg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func has(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// Capability reports which backends the host can serve.
func NFSAvailable() bool   { return has("mount.nfs") || has("mount") }
func CIFSAvailable() bool  { return has("mount.cifs") }
func CephAvailable() bool  { return has("mount.ceph") }
func ISCSIAvailable() bool { return has("iscsiadm") }

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// NFSMount mounts an NFS export at mountpoint. clientAddr (the storage NIC IP),
// when set, pins the NFSv4 client source address to the storage network.
func NFSMount(server, export, mountpoint, clientAddr, vers, extra string) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	src := server + ":" + export
	// Explicit version requested: honour it exactly (no auto-fallback), and pick
	// the right fstype. clientaddr only applies to NFSv4.
	if vers != "" && vers != "auto" {
		opts := "vers=" + vers + ",soft,timeo=100,retrans=3"
		if clientAddr != "" && strings.HasPrefix(vers, "4") {
			opts += ",clientaddr=" + clientAddr
		}
		if extra != "" {
			opts += "," + extra
		}
		fstype := "nfs4"
		if strings.HasPrefix(vers, "3") {
			fstype = "nfs"
		}
		_, err := run(30*time.Second, "mount", "-t", fstype, "-o", opts, src, mountpoint)
		return err
	}
	opts := "vers=4.2,soft,timeo=100,retrans=3"
	if clientAddr != "" {
		opts += ",clientaddr=" + clientAddr
	}
	if extra != "" {
		opts += "," + extra
	}
	_, err := run(30*time.Second, "mount", "-t", "nfs4", "-o", opts, src, mountpoint)
	if err != nil {
		// Fall back to NFSv3 (no clientaddr) for older servers.
		o3 := "vers=3,soft,timeo=100,retrans=3"
		if extra != "" {
			o3 += "," + extra
		}
		if _, e3 := run(30*time.Second, "mount", "-t", "nfs", "-o", o3, src, mountpoint); e3 == nil {
			return nil
		}
		return err
	}
	return nil
}

// CIFSMount mounts an SMB/CIFS share. creds "user%pass" via -o username/password.
func CIFSMount(unc, mountpoint, username, password, domain, vers, extra string) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	if vers == "" {
		vers = "3.0"
	}
	opts := "vers=" + vers
	if username != "" {
		opts += ",username=" + username + ",password=" + password
		if domain != "" {
			opts += ",domain=" + domain
		}
	} else {
		opts += ",guest"
	}
	if extra != "" {
		opts += "," + extra
	}
	_, err := run(30*time.Second, "mount", "-t", "cifs", "-o", opts, unc, mountpoint)
	return err
}

// CephMount mounts CephFS. mons is comma-separated monitor addresses, name is the
// cephx client name, secret its key. srcAddr pins the client to the storage NIC.
func CephMount(mons, path, mountpoint, name, secret, srcAddr, extra string) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	if path == "" {
		path = "/"
	}
	opts := "name=" + name + ",secret=" + secret
	// NOTE: the legacy `source_addr=` mount option was REMOVED from the modern
	// (Reef/Squid) Ceph kernel client and now makes mount fail with EINVAL
	// ("Invalid argument"). We no longer pass it; the client already routes over
	// the storage NIC because the mon addresses are on the storage subnet
	// (guardStorageTarget enforces that). srcAddr is kept in the signature for
	// compatibility but intentionally unused.
	_ = srcAddr
	if extra != "" {
		opts += "," + extra
	}
	src := mons + ":" + path
	_, err := run(30*time.Second, "mount", "-t", "ceph", "-o", opts, src, mountpoint)
	return err
}

// Unmount unmounts a mountpoint (lazy fallback if busy) and removes the dir.
func Unmount(mountpoint string) error {
	if _, err := run(15*time.Second, "umount", mountpoint); err != nil {
		if _, e2 := run(15*time.Second, "umount", "-l", mountpoint); e2 != nil {
			return err
		}
	}
	_ = os.Remove(mountpoint)
	return nil
}

// ---- iSCSI ----------------------------------------------------------------

// ISCSIDiscover runs sendtargets discovery against a portal and returns the
// discovered target IQNs.
func ISCSIDiscover(portal string) ([]string, error) {
	out, err := run(20*time.Second, "iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", portal)
	if err != nil {
		return nil, err
	}
	var iqns []string
	for _, line := range strings.Split(out, "\n") {
		// "10.0.0.5:3260,1 iqn.2004-04.com.example:target"
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[1], "iqn.") {
			iqns = append(iqns, f[1])
		}
	}
	return iqns, nil
}

// ISCSISession is one active iscsiadm session (as reported by the kernel).
type ISCSISession struct {
	Portal string
	Target string
}

// ISCSISessions returns the host's currently logged-in iSCSI sessions by parsing
// `iscsiadm -m session`. This is the authoritative "what's actually attached"
// list — the DB only records what was attached through the UI. Returns an empty
// list (no error) when there are no sessions (iscsiadm exits non-zero then).
func ISCSISessions() ([]ISCSISession, error) {
	if !ISCSIAvailable() {
		return nil, nil
	}
	// "tcp: [1] 10.10.4.10:3260,1 iqn.2025-10.local.teststor:vdx1 (non-flash)"
	out, err := run(10*time.Second, "iscsiadm", "-m", "session")
	if err != nil {
		// "No active sessions" → iscsiadm exits 21; treat as empty, not an error.
		return nil, nil
	}
	var sess []ISCSISession
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[3], "iqn.") {
			continue
		}
		portal := f[2]
		if i := strings.LastIndex(portal, ","); i >= 0 { // strip ",<tpgt>"
			portal = portal[:i]
		}
		sess = append(sess, ISCSISession{Portal: portal, Target: f[3]})
	}
	return sess, nil
}

// ISCSILogin logs into a target. When ifaceName is set, the session is bound to
// that iscsiadm iface (so it rides the storage NIC).
// CHAP holds optional iSCSI CHAP credentials. Username/Password authenticate the
// initiator to the target (one-way CHAP); InUsername/InPassword add mutual
// (two-way) CHAP where the target also authenticates to us.
type CHAP struct {
	Username, Password     string
	InUsername, InPassword string
}

func (c CHAP) set() bool { return c.Username != "" || c.Password != "" }

func ISCSILogin(portal, target, ifaceName string, chap CHAP) error {
	if ifaceName != "" {
		// Ensure an iscsi iface bound to the storage NIC exists (idempotent).
		_, _ = run(10*time.Second, "iscsiadm", "-m", "iface", "-I", ifaceName, "-o", "new")
		_, _ = run(10*time.Second, "iscsiadm", "-m", "iface", "-I", ifaceName, "-o", "update", "-n", "iface.net_ifacename", "-v", ifaceName)
	}
	// CHAP: set the auth on the node record BEFORE login. iscsiadm persists this
	// in its own node db (/etc/iscsi/nodes), so it also survives a reboot login.
	if chap.set() {
		upd := func(n, v string) {
			_, _ = run(10*time.Second, "iscsiadm", "-m", "node", "-T", target, "-p", portal, "-o", "update", "-n", n, "-v", v)
		}
		upd("node.session.auth.authmethod", "CHAP")
		upd("node.session.auth.username", chap.Username)
		upd("node.session.auth.password", chap.Password)
		if chap.InUsername != "" { // mutual (two-way) CHAP
			upd("node.session.auth.username_in", chap.InUsername)
			upd("node.session.auth.password_in", chap.InPassword)
		}
	}
	args := []string{"-m", "node", "-T", target, "-p", portal}
	if ifaceName != "" {
		args = append(args, "-I", ifaceName)
	}
	args = append(args, "--login")
	_, err := run(30*time.Second, "iscsiadm", args...)
	return err
}

// ISCSILogout logs out of a target session.
func ISCSILogout(portal, target string) error {
	_, err := run(30*time.Second, "iscsiadm", "-m", "node", "-T", target, "-p", portal, "--logout")
	return err
}
