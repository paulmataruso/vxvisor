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
func NFSMount(server, export, mountpoint, clientAddr, extra string) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	opts := "vers=4.2,soft,timeo=100,retrans=3"
	if clientAddr != "" {
		opts += ",clientaddr=" + clientAddr
	}
	if extra != "" {
		opts += "," + extra
	}
	src := server + ":" + export
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
func CIFSMount(unc, mountpoint, username, password, extra string) error {
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return err
	}
	opts := "vers=3.0"
	if username != "" {
		opts += ",username=" + username + ",password=" + password
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
	if srcAddr != "" {
		opts += ",source_addr=" + srcAddr
	}
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

// ISCSILogin logs into a target. When ifaceName is set, the session is bound to
// that iscsiadm iface (so it rides the storage NIC).
func ISCSILogin(portal, target, ifaceName string) error {
	if ifaceName != "" {
		// Ensure an iscsi iface bound to the storage NIC exists (idempotent).
		_, _ = run(10*time.Second, "iscsiadm", "-m", "iface", "-I", ifaceName, "-o", "new")
		_, _ = run(10*time.Second, "iscsiadm", "-m", "iface", "-I", ifaceName, "-o", "update", "-n", "iface.net_ifacename", "-v", ifaceName)
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
