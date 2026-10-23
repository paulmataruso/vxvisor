package service

import (
	"database/sql"
	"encoding/json"
	"net"
	"regexp"
	"strings"

	"vdxclone/internal/netdrv"
)

// East-West enforcement engine for the unified firewall (fw_compile.go compiles
// the org document down to these per-network configs). A "zone" here is just a
// MAC set and a "policy" an ordered MAC-pair rule; they are rendered into ONE
// host nftables BRIDGE-family table (bridge vdxdfw) with a default-ACCEPT chain,
// so enabling a live segment never blackholes it. Host-safe: a dedicated bridge
// table, never the L3 inet vdxclone table.
//
// These types/renderers are the stable backend; the authoring model (VM Groups,
// Internal/External zones, N-S/E-W rules) lives in fw_service.go.

var reDPortSvc = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)

// PGZone is a microseg zone: a label owning VM members (by MAC).
type PGZone struct {
	Name string   `json:"name"`
	MACs []string `json:"macs"`
}

// PGPolicy is one ordered zone-pair rule (default chain policy is accept, so a
// deny drops matching east-west frames and everything else still passes).
type PGPolicy struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Action string `json:"action"` // allow | deny
	Proto  string `json:"proto"`  // any | tcp | udp | icmp
	DPort  string `json:"dport"`
	Desc   string `json:"desc"`
}

// PGFirewall is the per-network microseg config (stored, as DERIVED output of
// the compiler, in net_firewall.fw_json).
type PGFirewall struct {
	Enabled  bool       `json:"enabled"`
	Zones    []PGZone   `json:"zones"`
	Policies []PGPolicy `json:"policies"`
}

func parsePGFW(blob string) PGFirewall {
	var f PGFirewall
	if strings.TrimSpace(blob) != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &f)
	}
	return f
}

// ---- rendering (pure, host-safe) -----------------------------------------

// renderBridgeFW builds the whole `bridge vdxdfw` table from every enabled
// per-network config. All policies share one chain; matching is by MAC, which is
// globally unique, so there's no cross-network ambiguity. Returns "" when there's
// nothing to enforce (the caller then removes the table).
func renderBridgeFW(fws []PGFirewall) string {
	var lines []string
	for _, f := range fws {
		if !f.Enabled {
			continue
		}
		macsByZone := map[string][]string{}
		for _, z := range f.Zones {
			macsByZone[z.Name] = validMACs(z.MACs)
		}
		for _, pol := range f.Policies {
			from := macsByZone[pol.From]
			to := macsByZone[pol.To]
			if len(from) == 0 || len(to) == 0 {
				continue
			}
			line := "    ether saddr " + macSet(from) + " ether daddr " + macSet(to)
			switch pol.Proto {
			case "tcp", "udp":
				line += " ether type ip " + pol.Proto
				if dp := strings.TrimSpace(pol.DPort); dp != "" {
					line += " dport " + dp
				}
			case "icmp":
				line += " ether type ip ip protocol icmp"
			}
			if pol.Action == "deny" {
				line += " drop"
			} else {
				line += " accept"
			}
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("table bridge " + netdrv.BridgeFWTable + " {\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority -200; policy accept;\n")
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func validMACs(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range in {
		m = strings.ToLower(strings.TrimSpace(m))
		if _, err := net.ParseMAC(m); err == nil && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func macSet(macs []string) string {
	if len(macs) == 1 {
		return macs[0]
	}
	return "{ " + strings.Join(macs, ", ") + " }"
}

// applyAllNetFW re-renders the shared bridge table from every network's derived
// config and applies it on the host. Called by the compiler and at boot.
func (s *Service) applyAllNetFW() error {
	rows, err := s.db.Query(`SELECT fw_json FROM net_firewall`)
	if err != nil {
		if err == sql.ErrNoRows {
			return netdrv.ReplaceBridgeFW("")
		}
		return err
	}
	var fws []PGFirewall
	for rows.Next() {
		var blob string
		if rows.Scan(&blob) == nil {
			fws = append(fws, parsePGFW(blob))
		}
	}
	rows.Close()
	return netdrv.ReplaceBridgeFW(renderBridgeFW(fws))
}

// ReensureNetFirewalls rebuilds the host bridge firewall table at boot (the
// kernel clears it on reboot). Called from the worker boot hook.
func (s *Service) ReensureNetFirewalls() { _ = s.applyAllNetFW() }
