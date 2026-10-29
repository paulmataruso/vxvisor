package session

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/qemu"
)

// How a VM's NIC attaches to the host, who its QEMU runs as, and the host-side
// guard that keeps a user-mode (SLIRP) guest off the host's loopback services.

// ErrTenantNoPortGroup is returned when a tenant org's VM would run without one
// of its own vSwitch-backed port groups. The fallback (the global cluster bridge
// every org shares, or SLIRP NAT out of the host) would void tenant isolation.
var ErrTenantNoPortGroup = errors.New("instances in this organization must be attached to one of its own port groups (the shared provider network isn't available to tenant organizations) — choose one of the organization's port groups")

// IsTenantOrg reports whether orgID is a tenant org: any org other than the
// provider's Default org (slug 'default', backfilled by migration 3 and never
// renamed). The Default org keeps the historical fallbacks (no port group = the
// global network mode); a tenant org's VMs must always sit on their own port
// group. An unknown org counts as a tenant (fail closed).
func (m *Manager) IsTenantOrg(orgID int64) bool {
	var slug string
	if err := m.db.QueryRow(`SELECT slug FROM orgs WHERE id=?`, orgID).Scan(&slug); err != nil {
		return true
	}
	return slug != "default"
}

// portGroup is the slice of a networks row the attach and IPAM paths need.
type portGroup struct {
	ID, OrgID          int64
	Name, Mode, Bridge string
	VLAN               int
	CIDR, Gateway      string
	PoolStart, PoolEnd string
}

// portGroup loads one of orgID's port groups (never another org's).
func (m *Manager) portGroup(orgID, id int64) (portGroup, error) {
	var pg portGroup
	err := m.db.QueryRow(`SELECT id,org_id,name,mode,COALESCE(bridge,''),COALESCE(vlan_id,0),
		COALESCE(cidr,''),COALESCE(gateway,''),COALESCE(pool_start,''),COALESCE(pool_end,'')
		FROM networks WHERE id=? AND org_id=?`, id, orgID).
		Scan(&pg.ID, &pg.OrgID, &pg.Name, &pg.Mode, &pg.Bridge, &pg.VLAN, &pg.CIDR, &pg.Gateway, &pg.PoolStart, &pg.PoolEnd)
	if err != nil {
		return pg, fmt.Errorf("unknown port group")
	}
	return pg, nil
}

// CheckPortGroup validates binding a VM of orgID to port group networkID: a
// non-zero id must be one of the org's own; a tenant org may use neither 0 (the
// shared provider network) nor a bridgeless (user-mode NAT) port group. The
// service layer calls it for a friendly error; Create, SetNetwork and Start
// re-check at the sink.
func (m *Manager) CheckPortGroup(orgID, networkID int64) error {
	if networkID == 0 {
		if m.IsTenantOrg(orgID) {
			return ErrTenantNoPortGroup
		}
		return nil
	}
	pg, err := m.portGroup(orgID, networkID)
	if err != nil {
		return err
	}
	if pg.Bridge == "" && m.IsTenantOrg(orgID) {
		return fmt.Errorf("port group %q is user-mode NAT with no vSwitch — instances in this organization need a vSwitch-backed port group", pg.Name)
	}
	return nil
}

// defaultTenantNetwork returns the backing port group of orgID's default tenant
// network, or 0 when it has none.
func (m *Manager) defaultTenantNetwork(orgID int64) int64 {
	var id int64
	_ = m.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE org_id=? AND is_default=1 LIMIT 1`, orgID).Scan(&id)
	return id
}

// nicPlan is how a VM's NIC attaches on this host.
type nicPlan struct {
	UserNet bool   // SLIRP user networking (no tap)
	Bridge  string // vdxd creates the VM's tap on this bridge ("" = no vdxd tap)
	VLAN    int    // access-port PVID on Bridge (0 = untagged)
	MTU     int    // Bridge's MTU (0 = unknown)
}

// planNIC resolves where a VM's NIC goes. A VM bound to a bridged port group
// ALWAYS gets a tap on that port group's bridge, whatever the global [network]
// mode — falling back to SLIRP there would silently void tenant isolation. Only
// a VM with no (or a bridgeless) port group follows the global mode, and only in
// the Default org: a tenant-org VM never falls back to the shared network.
func (m *Manager) planNIC(s *Session) (nicPlan, error) {
	br, vl, attach, err := m.resolveTapTarget(s)
	if err != nil {
		return nicPlan{}, err
	}
	if !attach {
		if m.IsTenantOrg(s.OrgID) {
			return nicPlan{}, ErrTenantNoPortGroup
		}
		switch m.cfg.Network.Mode {
		case "bridge", "overlay":
			br, vl = m.cfg.Cluster.Bridge, 0
		case "user":
			return nicPlan{UserNet: true}, nil
		default:
			return nicPlan{}, nil // legacy: a QEMU-managed tap with no bridge
		}
	}
	return nicPlan{Bridge: br, VLAN: vl, MTU: netdrv.LinkMTU(br)}, nil
}

// guestMTUOf returns the MTU a running VM's NIC was started with: the virtio
// host_mtu read back from its live QEMU command line, else the 1500 default.
func guestMTUOf(pid int) int {
	if mtu := hostMTUFromArgs(procArgs(pid)); mtu > 0 {
		return mtu
	}
	return 1500
}

// procArgs reads a process's argv (nil if it is gone).
func procArgs(pid int) []string {
	if pid <= 0 {
		return nil
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(raw) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
}

// hostMTUFromArgs extracts host_mtu=N from a QEMU argv's -device list (0 if none).
func hostMTUFromArgs(args []string) int {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-device" {
			continue
		}
		for _, f := range strings.Split(args[i+1], ",") {
			if v, ok := strings.CutPrefix(f, "host_mtu="); ok {
				if n, err := strconv.Atoi(v); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

// userNetFromArgs reports whether a QEMU argv uses SLIRP (-netdev user,...), and
// whether the argv was readable at all.
func userNetFromArgs(args []string) (user, known bool) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-netdev" {
			return strings.HasPrefix(args[i+1], "user,"), true
		}
	}
	return false, false
}

// ---- QEMU launch identity + SLIRP loopback guard -------------------------

type qemuIdent struct {
	UID, GID uint32
	Groups   []uint32
	RunAs    bool // dropped to [vm] run_as (its files must be chowned to it)
}

// qemuIdentity decides who QEMU runs as: the [vm] run_as user when set (and a
// real non-root user), otherwise root with the dedicated guard group as its
// primary gid — so the SLIRP loopback guard can single out QEMU's sockets either
// way (meta skuid / meta skgid).
func (m *Manager) qemuIdentity() (qemuIdent, error) {
	if m.cfg.VM.RunAs != "" {
		if uid, gid, groups, ok := lookupUser(m.cfg.VM.RunAs); ok && uid != 0 {
			return qemuIdent{UID: uid, GID: gid, Groups: groups, RunAs: true}, nil
		}
		log.Printf("qemu: [vm] run_as %q is not a usable non-root user — running QEMU as root", m.cfg.VM.RunAs)
	}
	gid, err := netdrv.EnsureGuardGroup()
	if err != nil {
		return qemuIdent{}, err
	}
	// Keep root's own groups (incl. kvm) — only the PRIMARY gid changes.
	groups := []uint32{0}
	if gs, err := os.Getgroups(); err == nil {
		for _, g := range gs {
			if g > 0 && uint32(g) != gid {
				groups = append(groups, uint32(g))
			}
		}
	}
	return qemuIdent{GID: gid, Groups: groups}, nil
}

// launchAs sets spec's launch identity (see qemuIdentity) and hands the VM's
// runtime files to a run-as user. A SLIRP VM must be matchable by the loopback
// guard, so failing to establish its identity or load the guard refuses the
// launch; a tapped VM just falls back to plain root.
func (m *Manager) launchAs(spec *qemu.Spec, files ...string) error {
	spec.RunAsUID, spec.RunAsGID, spec.RunAsGroups = 0, 0, nil
	id, err := m.qemuIdentity()
	if err != nil {
		if spec.UserNet {
			return fmt.Errorf("refusing to start a user-mode (NAT) VM without the host loopback guard: %w", err)
		}
		log.Printf("qemu: %v — launching %s as plain root", err, spec.ID)
		return nil
	}
	if id.RunAs {
		// The dropped-privilege QEMU must own its disk/NVRAM/seed/password
		// files, and be able to create the QMP socket in the disk dir.
		for _, f := range files {
			if f != "" {
				_ = qemu.Chown(f, id.UID, id.GID)
			}
		}
		_ = qemu.Chown(m.cfg.Paths.DiskDir, id.UID, id.GID)
	}
	spec.RunAsUID, spec.RunAsGID, spec.RunAsGroups = id.UID, id.GID, id.Groups
	if spec.UserNet {
		if err := m.ensureSlirpGuard(); err != nil {
			return fmt.Errorf("refusing to start a user-mode (NAT) VM: %w", err)
		}
	}
	return nil
}

// ensureSlirpGuard (re)loads the host nft guard for every identity QEMU may run
// under: the run-as uid and the guard group (both, so changing [vm] run_as
// between restarts never unguards an already-running VM).
func (m *Manager) ensureSlirpGuard() error {
	var uid uint32
	if m.cfg.VM.RunAs != "" {
		if u, _, _, ok := lookupUser(m.cfg.VM.RunAs); ok {
			uid = u
		}
	}
	gid, gerr := netdrv.EnsureGuardGroup()
	if gerr != nil && uid == 0 {
		return gerr
	}
	return netdrv.ApplySlirpGuard(uid, gid)
}

// StartSlirpGuard loads the SLIRP loopback guard now and keeps it loaded: an
// external `nft flush ruleset` (e.g. a restart of the nftables service) would
// otherwise silently unguard running user-mode VMs until the next VM launch,
// which re-applies it. Call once at daemon startup, before any VM starts.
func (m *Manager) StartSlirpGuard() {
	if err := m.ensureSlirpGuard(); err != nil {
		log.Printf("slirp guard: %v — user-mode (NAT) VMs will refuse to start until this is fixed", err)
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			if netdrv.SlirpGuardPresent() {
				continue
			}
			if err := m.ensureSlirpGuard(); err == nil {
				log.Printf("slirp guard: table inet %s was missing (ruleset flushed?) — re-applied", netdrv.SlirpGuardTable)
			}
		}
	}()
}

// prepareReceiverSpec makes a shipped migration-receiver spec safe and local:
// the id must be a session uuid (it names local files), the console password
// moves into this node's own 0600 secret file (never the command line), and the
// launch identity is recomputed here — never trusted from the wire.
func (m *Manager) prepareReceiverSpec(spec *qemu.Spec) error {
	if _, err := uuid.Parse(spec.ID); err != nil {
		return fmt.Errorf("receiver spec: invalid instance id")
	}
	spec.VNCPwFile = ""
	if spec.VNCPassword != "" {
		pwFile := filepath.Join(m.cfg.Paths.DiskDir, spec.ID+".vncpw")
		if err := qemu.WriteSecretFile(pwFile, spec.VNCPassword); err != nil {
			return fmt.Errorf("receiver VNC secret: %w", err)
		}
		spec.VNCPwFile = pwFile
		spec.VNCPassword = ""
	}
	return m.launchAs(spec, spec.DiskPath, spec.OVMFVarsPath, spec.SeedISO, spec.VNCPwFile)
}

// isNoRows is sql.ErrNoRows-aware error matching for the resolvers above.
func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
