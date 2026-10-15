package qemu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// qemu-guest-agent (QGA) client. The guest agent speaks the QMP wire format
// (one JSON object per line) but, unlike the QMP monitor, does NOT implement
// qmp_capabilities — so we must NOT reuse DialQMP's handshake here. We just open
// the socket and issue guest-* commands with a hard deadline so a dead or absent
// agent can never stall a page render.
//
// All commands used here are READ-ONLY. guest-exec and other state-changing
// commands are deliberately never issued from the control plane.

// GuestInfo is the subset of guest-agent data surfaced in the UI.
type GuestInfo struct {
	Responsive bool          `json:"responsive"`
	Hostname   string        `json:"hostname,omitempty"`
	OS         string        `json:"os,omitempty"`        // pretty OS name
	OSKernel   string        `json:"os_kernel,omitempty"` // kernel-release/version
	AgentVer   string        `json:"agent_version,omitempty"`
	Interfaces []GuestNIC    `json:"interfaces,omitempty"`
	Filesystems []GuestFS    `json:"filesystems,omitempty"`
}

// GuestNIC is one guest network interface with its addresses.
type GuestNIC struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

// GuestFS is one mounted guest filesystem with usage.
type GuestFS struct {
	Mount string `json:"mount"`
	Type  string `json:"type,omitempty"`
	Used  int64  `json:"used,omitempty"`
	Total int64  `json:"total,omitempty"`
}

// QueryGuestAgent connects to the VM's guest-agent socket and returns whatever
// it can within the deadline. A non-responsive/absent agent yields
// {Responsive:false} and a nil error — the caller renders "agent not available"
// rather than failing. Any transport/parse error also degrades to that.
func QueryGuestAgent(socketPath string) GuestInfo {
	gi := GuestInfo{}
	if socketPath == "" {
		return gi
	}
	conn, err := net.DialTimeout("unix", socketPath, 1500*time.Millisecond)
	if err != nil {
		return gi
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	r := bufio.NewReader(conn)

	// Liveness first. If the agent doesn't pong, stop — nothing else will answer.
	if _, err := qgaCall(conn, r, "guest-ping", nil); err != nil {
		return gi
	}
	gi.Responsive = true

	// Hostname.
	if raw, err := qgaCall(conn, r, "guest-get-host-name", nil); err == nil {
		var hn struct {
			HostName string `json:"host-name"`
		}
		if json.Unmarshal(raw, &hn) == nil {
			gi.Hostname = hn.HostName
		}
	}
	// OS info.
	if raw, err := qgaCall(conn, r, "guest-get-osinfo", nil); err == nil {
		var os struct {
			PrettyName    string `json:"pretty-name"`
			Name          string `json:"name"`
			Version       string `json:"version"`
			KernelRelease string `json:"kernel-release"`
			KernelVersion string `json:"kernel-version"`
		}
		if json.Unmarshal(raw, &os) == nil {
			gi.OS = os.PrettyName
			if gi.OS == "" {
				gi.OS = joinNonEmpty(os.Name, os.Version)
			}
			gi.OSKernel = os.KernelRelease
		}
	}
	// Agent version.
	if raw, err := qgaCall(conn, r, "guest-info", nil); err == nil {
		var info struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &info) == nil {
			gi.AgentVer = info.Version
		}
	}
	// Network interfaces + addresses.
	if raw, err := qgaCall(conn, r, "guest-network-get-interfaces", nil); err == nil {
		var ifs []struct {
			Name string `json:"name"`
			MAC  string `json:"hardware-address"`
			Addrs []struct {
				IP   string `json:"ip-address"`
				Type string `json:"ip-address-type"`
			} `json:"ip-addresses"`
		}
		if json.Unmarshal(raw, &ifs) == nil {
			for _, in := range ifs {
				if in.Name == "lo" {
					continue
				}
				n := GuestNIC{Name: in.Name, MAC: in.MAC}
				for _, a := range in.Addrs {
					n.IPs = append(n.IPs, a.IP)
				}
				gi.Interfaces = append(gi.Interfaces, n)
			}
		}
	}
	// Filesystem usage.
	if raw, err := qgaCall(conn, r, "guest-get-fsinfo", nil); err == nil {
		var fss []struct {
			Mount string `json:"mountpoint"`
			Type  string `json:"type"`
			Used  int64  `json:"used-bytes"`
			Total int64  `json:"total-bytes"`
		}
		if json.Unmarshal(raw, &fss) == nil {
			for _, f := range fss {
				gi.Filesystems = append(gi.Filesystems, GuestFS{
					Mount: f.Mount, Type: f.Type, Used: f.Used, Total: f.Total,
				})
			}
		}
	}
	return gi
}

// qgaCall writes one guest-agent command and reads one JSON reply, returning the
// raw "return" value. No qmp_capabilities handshake (the agent has none).
func qgaCall(conn net.Conn, r *bufio.Reader, cmd string, args map[string]any) (json.RawMessage, error) {
	req := map[string]any{"execute": cmd}
	if args != nil {
		req["arguments"] = args
	}
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	// Read lines until one carries a return or error (skip any async noise).
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Desc string `json:"desc"`
			} `json:"error"`
		}
		if json.Unmarshal(line, &resp) != nil {
			continue
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("guest-agent: %s", resp.Error.Desc)
		}
		if resp.Return != nil {
			return resp.Return, nil
		}
	}
}

func joinNonEmpty(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += " "
		}
		out += p
	}
	return out
}
