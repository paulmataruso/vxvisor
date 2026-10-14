// Package cloudinit builds a NoCloud "seed" ISO that cloud-init reads on first
// boot to create the login user, set its password, and install SSH keys.
//
// This is an original implementation of the publicly documented NoCloud data
// source: a filesystem labelled CIDATA containing a user-data (cloud-config)
// file and a meta-data file. It is not derived from any proprietary product.
package cloudinit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config is the first-boot identity written into the seed.
type Config struct {
	InstanceID string // stable id (the session UUID)
	Hostname   string
	Username   string
	Password   string // plaintext; set as the login password via chpasswd
	SSHKey     string // optional authorized public key

	// Static networking (bridge/overlay mode). When StaticIP is set (CIDR form,
	// e.g. 10.77.0.5/16) a NoCloud network-config pins it to the first NIC so the
	// guest comes up on a predictable, routable address — which is what the
	// desktop gateway targets for RDP and what survives a live migration.
	MAC         string
	StaticIP    string
	Gateway     string
	Nameservers []string

	// InstallRDP adds an xrdp server on first boot so the browser-desktop gateway
	// can offer a full RDP session (clipboard, audio, microphone, webcam) rather
	// than only the VNC framebuffer. Requires guest internet to fetch the package.
	InstallRDP bool

	// Desktop, when "xfce", installs a lightweight XFCE desktop + lightdm on first
	// boot so the VNC/SPICE console shows a graphical login. XFCE is far lighter
	// than GNOME and usable even on weak hosts. Requires guest internet.
	Desktop string
}

// userData renders a minimal, broadly-compatible cloud-config. It enables
// password SSH login and a passwordless-sudo admin user so a freshly booted
// cloud image is immediately usable from the console or over SSH.
func (c Config) userData() string {
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", yamlStr(c.Hostname))
	// Keep /etc/hosts in sync with the hostname so FQDN lookups succeed (avoids
	// the "make-ssl-cert: Could not get FQDN" / "hostname: Name or service not
	// known" warnings on first boot).
	b.WriteString("manage_etc_hosts: true\n")
	b.WriteString("users:\n")
	fmt.Fprintf(&b, "  - name: %s\n", yamlStr(c.Username))
	b.WriteString("    sudo: 'ALL=(ALL) NOPASSWD:ALL'\n")
	b.WriteString("    groups: [sudo]\n")
	b.WriteString("    shell: /bin/bash\n")
	b.WriteString("    lock_passwd: false\n")
	if c.SSHKey != "" {
		b.WriteString("    ssh_authorized_keys:\n")
		fmt.Fprintf(&b, "      - %s\n", yamlStr(strings.TrimSpace(c.SSHKey)))
	}
	b.WriteString("ssh_pwauth: true\n")
	b.WriteString("chpasswd:\n")
	b.WriteString("  expire: false\n")
	b.WriteString("  list: |\n")
	fmt.Fprintf(&b, "    %s:%s\n", c.Username, c.Password)
	var pkgs, cmds []string
	if c.InstallRDP {
		// A minimal XFCE + xrdp desktop so the guest answers RDP on :3389.
		pkgs = append(pkgs, "xrdp", "xfce4")
		cmds = append(cmds,
			"[ bash, -c, \"echo xfce4-session > /home/"+c.Username+"/.xsession\" ]",
			"[ systemctl, enable, --now, xrdp ]",
			"[ adduser, xrdp, ssl-cert ]")
	}
	if c.Desktop == "xfce" {
		// Lightweight graphical console: XFCE + lightdm on the local display.
		pkgs = append(pkgs, "xorg", "xfce4", "xfce4-goodies", "lightdm", "dbus-x11")
		cmds = append(cmds,
			"[ systemctl, set-default, graphical.target ]",
			"[ systemctl, enable, --now, lightdm ]")
	}
	if len(pkgs) > 0 {
		b.WriteString("package_update: true\n")
		b.WriteString("packages:\n")
		for _, p := range pkgs {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}
	if len(cmds) > 0 {
		b.WriteString("runcmd:\n")
		for _, c := range cmds {
			fmt.Fprintf(&b, "  - %s\n", c)
		}
	}
	return b.String()
}

func (c Config) metaData() string {
	return fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", c.InstanceID, c.Hostname)
}

// hasNetwork reports whether a static network-config should be emitted.
func (c Config) hasNetwork() bool { return c.StaticIP != "" }

// networkConfig renders a NoCloud network-config (netplan v2) that pins the
// static address to the NIC matching MAC (or the first NIC when MAC is empty).
func (c Config) networkConfig() string {
	var b strings.Builder
	b.WriteString("version: 2\n")
	b.WriteString("ethernets:\n")
	b.WriteString("  nic0:\n")
	if c.MAC != "" {
		b.WriteString("    match:\n")
		fmt.Fprintf(&b, "      macaddress: %s\n", yamlStr(c.MAC))
		b.WriteString("    set-name: nic0\n")
	} else {
		b.WriteString("    match: {name: \"e*\"}\n")
	}
	b.WriteString("    dhcp4: false\n")
	b.WriteString("    addresses:\n")
	fmt.Fprintf(&b, "      - %s\n", yamlStr(c.StaticIP))
	if c.Gateway != "" {
		b.WriteString("    routes:\n")
		fmt.Fprintf(&b, "      - {to: default, via: %s}\n", yamlStr(c.Gateway))
	}
	if len(c.Nameservers) > 0 {
		b.WriteString("    nameservers:\n")
		b.WriteString("      addresses: [")
		for i, ns := range c.Nameservers {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(yamlStr(ns))
		}
		b.WriteString("]\n")
	}
	return b.String()
}

// yamlStr single-quotes a scalar so names/keys with special characters stay
// valid YAML. Embedded single quotes are doubled per the YAML spec.
func yamlStr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// BuildSeedISO writes user-data/meta-data into a scratch dir and packs them into
// an ISO labelled CIDATA at isoPath. The plaintext password lives only in the
// seed file and the resulting ISO — it is never written to a log.
func BuildSeedISO(workDir, isoPath string, c Config) error {
	stage, err := os.MkdirTemp(workDir, "seed-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	if err := os.WriteFile(filepath.Join(stage, "user-data"), []byte(c.userData()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "meta-data"), []byte(c.metaData()), 0o600); err != nil {
		return err
	}
	files := []string{filepath.Join(stage, "user-data"), filepath.Join(stage, "meta-data")}
	if c.hasNetwork() {
		netPath := filepath.Join(stage, "network-config")
		if err := os.WriteFile(netPath, []byte(c.networkConfig()), 0o600); err != nil {
			return err
		}
		files = append(files, netPath)
	}

	args := append([]string{"-output", isoPath, "-volid", "CIDATA", "-joliet", "-rock"}, files...)
	cmd := exec.Command(isoTool(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build seed iso: %v: %s", err, out)
	}
	_ = os.Chmod(isoPath, 0o600)
	return nil
}

// isoTool returns the first available ISO authoring tool.
func isoTool() string {
	for _, t := range []string{"genisoimage", "mkisofs", "xorrisofs"} {
		if p, err := exec.LookPath(t); err == nil {
			return p
		}
	}
	return "genisoimage"
}

// Available reports whether an ISO authoring tool is installed.
func Available() bool {
	for _, t := range []string{"genisoimage", "mkisofs", "xorrisofs"} {
		if _, err := exec.LookPath(t); err == nil {
			return true
		}
	}
	return false
}
