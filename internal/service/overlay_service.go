package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"vdxclone/internal/sharedstg"
)

// ClusterPeerUnderlayIPs returns the underlay IPs of the OTHER live cluster
// members, for auto-peering a VXLAN segment across the cluster. It prefers each
// peer's cluster-net address (the dedicated inter-node link) and falls back to
// its management address, stripping any port. Empty on a single-host install.
func (s *Service) ClusterPeerUnderlayIPs(p *Principal) []string {
	if p == nil || !p.IsAdmin || s.role == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, pr := range s.role.Peers() {
		if pr.Self {
			continue
		}
		addr := pr.ClusterAddr
		if addr == "" {
			addr = pr.MgmtAddr
		}
		if h, _, err := net.SplitHostPort(addr); err == nil {
			addr = h
		}
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// MergePeerCSV unions a manual peer CSV with auto-discovered peer IPs, deduped.
func MergePeerCSV(manual string, auto []string) string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, v := range strings.Split(manual, ",") {
		add(v)
	}
	for _, v := range auto {
		add(v)
	}
	return strings.Join(out, ",")
}

// Storage overlays (VXLAN). An overlay gives the cluster a shared L2 for storage
// traffic that rides over an existing underlay (e.g. the management network) as
// UDP — the fix for a storage server that is not on the hosts' physical segment.
// The overlay interface then serves as the dedicated storage interface.
//
// Each overlay is persisted two ways: a DB row (for the UI) and a systemd oneshot
// unit (so the interface is recreated on boot). vdxd runs as root, so it can
// install + enable the unit.

const overlayUnitDir = "/etc/systemd/system"

var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// StorageOverlay is one configured VXLAN overlay (DB row + live status).
type StorageOverlay struct {
	ID          int64
	Name        string
	VNI         int
	UnderlayDev string
	LocalIP     string
	OverlayCIDR string
	DstPort     int
	MTU         int
	Peers       string // CSV
	CreatedAt   string
	Up          bool // the interface currently exists on this host
}

func (s *Service) overlayUnitPath(name string) string {
	return fmt.Sprintf("%s/vdx-overlay-%s.service", overlayUnitDir, name)
}

func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StorageOverlays lists configured overlays, each annotated with whether its
// interface is currently present on this host.
func (s *Service) StorageOverlays(p *Principal) ([]StorageOverlay, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,name,vni,underlay_dev,local_ip,overlay_cidr,dstport,mtu,peers,created_at FROM storage_overlays ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StorageOverlay
	for rows.Next() {
		var o StorageOverlay
		if rows.Scan(&o.ID, &o.Name, &o.VNI, &o.UnderlayDev, &o.LocalIP, &o.OverlayCIDR, &o.DstPort, &o.MTU, &o.Peers, &o.CreatedAt) == nil {
			o.Up = sharedstg.VXLANExists(o.Name)
			out = append(out, o)
		}
	}
	return out, nil
}

// AddStorageOverlay creates a VXLAN overlay: it brings the interface up now and
// installs a systemd unit so it returns on boot, then records it.
func (s *Service) AddStorageOverlay(p *Principal, name, underlayDev, localIP, overlayCIDR, peers string, vni, dstPort, mtu int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	name = strings.TrimSpace(name)
	if !ifaceNameRe.MatchString(name) {
		return fmt.Errorf("invalid interface name %q (letters, digits, _.- ; max 15 chars)", name)
	}
	if name == s.mgmtIface() {
		return fmt.Errorf("the overlay cannot reuse the management interface name")
	}
	if underlayDev == "" || localIP == "" || overlayCIDR == "" || vni <= 0 {
		return fmt.Errorf("underlay device, local IP, overlay CIDR and a VNI are required")
	}
	if dstPort <= 0 {
		dstPort = 4789
	}
	if mtu <= 0 {
		mtu = 1450
	}
	var peerList []string
	for _, pp := range strings.Split(peers, ",") {
		if pp = strings.TrimSpace(pp); pp != "" {
			peerList = append(peerList, pp)
		}
	}
	spec := sharedstg.VXLANSpec{
		Name: name, Dev: underlayDev, Local: localIP, OverlayCIDR: overlayCIDR,
		VNI: vni, DstPort: dstPort, MTU: mtu, Peers: peerList,
	}
	// Install + enable the systemd unit, which also brings the overlay up now
	// (enable --now runs ExecStart). This keeps one code path for boot + runtime.
	unit := sharedstg.VXLANUnit(spec)
	unitPath := s.overlayUnitPath(name)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write overlay unit: %w", err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		_ = os.Remove(unitPath)
		return err
	}
	if err := systemctl("enable", "--now", "vdx-overlay-"+name+".service"); err != nil {
		// Fall back to a direct runtime bring-up so the admin isn't blocked if
		// the unit failed to start for a transient reason; the unit still persists.
		if upErr := sharedstg.VXLANUp(spec); upErr != nil {
			_ = os.Remove(unitPath)
			_ = systemctl("daemon-reload")
			return fmt.Errorf("%v (and direct bring-up failed: %v)", err, upErr)
		}
	}
	if _, err := s.db.Exec(`INSERT INTO storage_overlays(name,vni,underlay_dev,local_ip,overlay_cidr,dstport,mtu,peers)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET vni=excluded.vni,underlay_dev=excluded.underlay_dev,local_ip=excluded.local_ip,
			overlay_cidr=excluded.overlay_cidr,dstport=excluded.dstport,mtu=excluded.mtu,peers=excluded.peers`,
		name, vni, underlayDev, localIP, overlayCIDR, dstPort, mtu, strings.Join(peerList, ",")); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "storage.overlay.add", "overlay", name, ip, map[string]any{"vni": vni, "dev": underlayDev})
	return nil
}

// DeleteStorageOverlay tears down an overlay: stop + disable + remove its unit,
// then delete the record. Refuses while the overlay is the active storage iface.
func (s *Service) DeleteStorageOverlay(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var name string
	if err := s.db.QueryRow(`SELECT name FROM storage_overlays WHERE id=?`, id).Scan(&name); err != nil {
		return err
	}
	if name == s.StorageIface() {
		return fmt.Errorf("overlay %s is the active storage interface — change the storage interface first", name)
	}
	_ = systemctl("disable", "--now", "vdx-overlay-"+name+".service")
	_ = sharedstg.VXLANDown(name) // in case the unit was absent
	_ = os.Remove(s.overlayUnitPath(name))
	_ = systemctl("daemon-reload")
	if _, err := s.db.Exec(`DELETE FROM storage_overlays WHERE id=?`, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "storage.overlay.delete", "overlay", name, ip, nil)
	return nil
}
