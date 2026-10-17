// Package remoteprov provisions a brand-new worker node over SSH: it configures
// the node's management + cluster network interfaces with a REBOOT-SAFE,
// time-based rollback so the operation can never strand the node, then (optionally)
// installs the vdxd binary. Everything here is driven through the Runner interface
// so the provisioning sequence is unit-testable with a mock SSH transport.
package remoteprov

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Runner executes commands on a remote host. stdin, when non-nil, is fed to the
// command. Implemented by SSHRunner (real) and a mock in tests.
type Runner interface {
	// Run executes cmd as the login user. Returns stdout, stderr, the exit code,
	// and a transport error (nil if the command merely exited non-zero).
	Run(cmd string, stdin []byte) (stdout, stderr string, code int, err error)
	// SudoRun executes cmd with root privileges (direct if the login user is root,
	// else via `sudo -S` with the password fed on the first stdin line — the
	// password is NEVER placed in the command string, so it can't leak to logs or
	// the process table). Any provided stdin follows the password line.
	SudoRun(cmd string, stdin []byte) (stdout, stderr string, code int, err error)
	Close() error
}

// SSHRunner is a real SSH transport.
type SSHRunner struct {
	cli     *ssh.Client
	user    string
	pass    string // login/sudo password; kept in memory only, never logged
	HostKey string // captured SHA256 fingerprint (TOFU)
}

func hostPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "22")
}

// Dial connects with trust-on-first-use: it captures the host key fingerprint
// (returned so the caller can pin it for the rest of the join). Prefer a key if
// given, else password.
func Dial(addr, user, pass, keyPEM string) (*SSHRunner, string, error) {
	return dial(addr, user, pass, keyPEM, "")
}

// DialPinned connects and REQUIRES the host key to match expectFP (set from a
// prior Dial), closing the MITM window on later connects in the same join.
func DialPinned(addr, user, pass, keyPEM, expectFP string) (*SSHRunner, error) {
	r, _, err := dial(addr, user, pass, keyPEM, expectFP)
	return r, err
}

func dial(addr, user, pass, keyPEM, expectFP string) (*SSHRunner, string, error) {
	var auths []ssh.AuthMethod
	if strings.TrimSpace(keyPEM) != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(keyPEM)); err == nil {
			auths = append(auths, ssh.PublicKeys(signer))
		} else {
			return nil, "", fmt.Errorf("parse private key: %w", err)
		}
	}
	if pass != "" {
		auths = append(auths, ssh.Password(pass))
	}
	if len(auths) == 0 {
		return nil, "", fmt.Errorf("no SSH credentials provided")
	}
	var captured string
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = ssh.FingerprintSHA256(key)
			if expectFP != "" && captured != expectFP {
				return fmt.Errorf("host key changed (possible MITM): got %s, expected %s", captured, expectFP)
			}
			return nil
		},
		Timeout: 12 * time.Second,
	}
	cli, err := ssh.Dial("tcp", hostPort(addr), cfg)
	if err != nil {
		return nil, captured, err
	}
	return &SSHRunner{cli: cli, user: user, pass: pass, HostKey: captured}, captured, nil
}

func (r *SSHRunner) Run(cmd string, stdin []byte) (string, string, int, error) {
	sess, err := r.cli.NewSession()
	if err != nil {
		return "", "", -1, err
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	err = sess.Run(cmd)
	if ee, ok := err.(*ssh.ExitError); ok {
		return out.String(), errb.String(), ee.ExitStatus(), nil
	}
	if err != nil {
		return out.String(), errb.String(), -1, err
	}
	return out.String(), errb.String(), 0, nil
}

func (r *SSHRunner) SudoRun(cmd string, stdin []byte) (string, string, int, error) {
	if r.user == "root" {
		return r.Run(cmd, stdin)
	}
	// Feed the sudo password as the first stdin line; the command's own stdin (if
	// any) follows it. `sudo -S -p ''` reads exactly one line for the password.
	var in bytes.Buffer
	in.WriteString(r.pass)
	in.WriteByte('\n')
	if stdin != nil {
		in.Write(stdin)
	}
	full := "sudo -S -p '' bash -c " + shellSingleQuote(cmd)
	return r.Run(full, in.Bytes())
}

func (r *SSHRunner) Close() error {
	if r.cli != nil {
		return r.cli.Close()
	}
	return nil
}

// shellSingleQuote wraps s in single quotes, escaping embedded single quotes, so
// it survives as one argument to `bash -c`.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
