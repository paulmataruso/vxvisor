package lxc

import (
	"os"
	"os/exec"
)

// ConsoleCmd returns a command that opens an interactive root session INSIDE the
// container via lxc-attach, wired to a PTY by the caller. It runs `login -f root`
// so the user gets the full login experience (MOTD + a proper shell prompt),
// exactly like Proxmox's container console. IMPORTANT: the command is run
// DIRECTLY (no `sh -c "exec …"` wrapper) — wrapping it breaks the controlling-tty
// handoff and the shell then starts non-interactive (blank, no prompt).
func ConsoleCmd(name, lxcpath string) *exec.Cmd {
	login := loginPath(name, lxcpath)
	var cmd *exec.Cmd
	if login != "" {
		cmd = exec.Command("lxc-attach", append(pathArgs(lxcpath), "-n", name, "--", login, "-f", "root")...)
	} else {
		// Minimal images without login/util-linux: fall back to an interactive
		// shell, still run directly so it stays a real terminal.
		shell := "/bin/sh"
		if containerHas(name, lxcpath, "/bin/bash") {
			shell = "/bin/bash"
		}
		cmd = exec.Command("lxc-attach", append(pathArgs(lxcpath), "-n", name, "--", shell, "-i")...)
	}
	cmd.Env = []string{"TERM=xterm-256color"}
	return cmd
}

// loginPath returns the container's login binary path, or "" if none exists.
func loginPath(name, lxcpath string) string {
	for _, p := range []string{"/bin/login", "/usr/bin/login", "/sbin/login"} {
		if containerHas(name, lxcpath, p) {
			return p
		}
	}
	return ""
}

// containerHas reports whether a path exists inside the container's rootfs.
func containerHas(name, lxcpath, path string) bool {
	root := basePath(lxcpath) + "/" + name + "/rootfs"
	if _, err := os.Stat(root + path); err == nil {
		return true
	}
	return false
}
