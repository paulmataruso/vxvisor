// Package netdrv is the host network driver: it renders and applies the host
// side of a VM's networking (tap devices on a bridge, 802.1q VLANs, and nftables
// rulesets) and owns the networking data model (networks, IP leases, port
// forwards, firewall rules).
//
// The "user" mode needs no host changes — QEMU's SLIRP stack plus hostfwd port
// forwarding provide NAT and reachability with zero privilege. The bridge/vlan
// code paths change host networking and are only exercised when an operator
// explicitly attaches a NIC to a bridge/vlan network with a pre-existing bridge.
package netdrv

import (
	"crypto/rand"
	"fmt"
	"os/exec"
	"strings"

	"vdxclone/internal/db"
)

// ---- driver: MAC + tap + nftables (pure render / gated apply) -------------

// GenMAC returns a locally-administered unicast MAC (02:...), stable per call.
func GenMAC() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", b[0], b[1], b[2])
}

// TapName derives a deterministic, interface-name-length-safe tap name for a
// session (Linux IFNAMSIZ limits names to 15 characters).
func TapName(sessionID string) string {
	id := strings.ReplaceAll(sessionID, "-", "")
	if len(id) > 11 {
		id = id[:11]
	}
	return "vdxt" + id
}

// SetupTap creates a tap device and enslaves it to a bridge. It is idempotent
// enough for restart: a pre-existing tap is reused.
func SetupTap(tap, bridge string) error {
	if !ifaceExists(tap) {
		if err := run("ip", "tuntap", "add", tap, "mode", "tap"); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", tap, "up"); err != nil {
		return err
	}
	return run("ip", "link", "set", tap, "master", bridge)
}

// TeardownTap removes a tap device (best effort).
func TeardownTap(tap string) { _ = run("ip", "link", "del", tap) }

func ifaceExists(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// RenderNFT renders an nftables ruleset for a network's firewall rules. It is a
// pure function (no host interaction) so it can be unit-tested and reviewed
// before being applied with ApplyNFT.
func RenderNFT(table string, rules []FirewallRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	for _, r := range rules {
		line := "    "
		if r.Proto != "" {
			line += r.Proto + " "
		}
		if r.DPort != "" {
			line += "dport " + r.DPort + " "
		}
		if r.Source != "" {
			line += "ip saddr " + r.Source + " "
		}
		action := r.Action
		if action == "" {
			action = "accept"
		}
		line += action
		b.WriteString(line + "\n")
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// ApplyNFT loads a rendered ruleset via `nft -f -`.
func ApplyNFT(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply: %v: %s", err, out)
	}
	return nil
}

// ---- data store ----------------------------------------------------------

type Store struct{ db *db.DB }

func New(d *db.DB) *Store { return &Store{db: d} }

type Network struct {
	ID        int64
	OrgID     int64
	Name      string
	Mode      string
	Bridge    string
	VLANID    int
	CIDR      string
	Gateway   string
	PoolStart string
	PoolEnd   string
	CreatedAt string
}

func (s *Store) CreateNetwork(n Network) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end)
		VALUES(?,?,?,?,?,?,?,?,?)`, n.OrgID, n.Name, n.Mode, n.Bridge, n.VLANID, n.CIDR, n.Gateway, n.PoolStart, n.PoolEnd)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListNetworks(orgID int64) ([]Network, error) {
	rows, err := s.db.Query(`SELECT id,org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end,created_at
		FROM networks WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.OrgID, &n.Name, &n.Mode, &n.Bridge, &n.VLANID, &n.CIDR, &n.Gateway, &n.PoolStart, &n.PoolEnd, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNetwork(orgID, id int64) (Network, error) {
	var n Network
	err := s.db.QueryRow(`SELECT id,org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end,created_at
		FROM networks WHERE id=? AND org_id=?`, id, orgID).
		Scan(&n.ID, &n.OrgID, &n.Name, &n.Mode, &n.Bridge, &n.VLANID, &n.CIDR, &n.Gateway, &n.PoolStart, &n.PoolEnd, &n.CreatedAt)
	return n, err
}

func (s *Store) DeleteNetwork(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM networks WHERE id=? AND org_id=?`, id, orgID)
	return err
}

type PortForward struct {
	ID        int64
	SessionID string
	Proto     string
	HostIP    string
	HostPort  int
	GuestPort int
	Label     string
	CreatedAt string
}

// AllocHostPort returns the lowest free host port at/above base not already
// used by a forward.
func (s *Store) AllocHostPort(base int) (int, error) {
	used := map[int]bool{}
	rows, err := s.db.Query(`SELECT host_port FROM port_forwards`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err == nil {
			used[p] = true
		}
	}
	rows.Close()
	for p := base; p < base+5000; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free host port")
}

func (s *Store) AddPortForward(pf PortForward) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO port_forwards(session_id,proto,host_ip,host_port,guest_port,label)
		VALUES(?,?,?,?,?,?)`, pf.SessionID, pf.Proto, pf.HostIP, pf.HostPort, pf.GuestPort, pf.Label)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListPortForwards(sessionID string) ([]PortForward, error) {
	rows, err := s.db.Query(`SELECT id,session_id,proto,host_ip,host_port,guest_port,label,created_at
		FROM port_forwards WHERE session_id=? ORDER BY host_port`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortForward
	for rows.Next() {
		var pf PortForward
		if err := rows.Scan(&pf.ID, &pf.SessionID, &pf.Proto, &pf.HostIP, &pf.HostPort, &pf.GuestPort, &pf.Label, &pf.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, pf)
	}
	return out, rows.Err()
}

func (s *Store) DeletePortForward(sessionID string, id int64) error {
	_, err := s.db.Exec(`DELETE FROM port_forwards WHERE id=? AND session_id=?`, id, sessionID)
	return err
}

type FirewallRule struct {
	ID        int64
	NetworkID int64
	Priority  int
	Action    string
	Proto     string
	DPort     string
	Source    string
}

func (s *Store) ListFirewallRules(networkID int64) ([]FirewallRule, error) {
	rows, err := s.db.Query(`SELECT id,network_id,priority,action,proto,dport,source
		FROM firewall_rules WHERE network_id=? ORDER BY priority`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirewallRule
	for rows.Next() {
		var r FirewallRule
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.Priority, &r.Action, &r.Proto, &r.DPort, &r.Source); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
