package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"vdxclone/internal/netdrv"
)

// VIPManager owns the floating management VIP while this node is leader. It is
// driven by Role's promote/demote callbacks: on promote it brings up the macvlan
// child with the cluster-stable MAC and acquires an address (DHCP or static); on
// demote it tears the child down. Strict release-before-claim is inherent — a
// node only acquires after it has become leader, and the prior leader releases on
// demote, so the MAC/IP is never held by two nodes at once in the common path.
type VIPManager struct {
	child    string // macvlan child iface name
	parent   string // mgmt NIC (ens18)
	dhcp     bool
	static   string // static CIDR when !dhcp
	mac      string // stable, cluster-derived MAC
	clientID string // DHCP client-id pinned to the MAC
	role     *Role
}

// NewVIPManager builds a VIP manager. secret seeds the deterministic MAC so every
// node computes the same one (lease affinity makes the IP float). parent is the
// mgmt NIC; dhcp picks DHCP vs the static CIDR.
func NewVIPManager(role *Role, secret []byte, parent, static string, dhcp bool) *VIPManager {
	mac := vipMAC(secret)
	return &VIPManager{
		child:    "vdxvip0",
		parent:   parent,
		dhcp:     dhcp,
		static:   static,
		mac:      mac,
		clientID: "01:" + mac, // RFC2132 type-01 (ethernet) + MAC
		role:     role,
	}
}

// Attach wires the VIP lifecycle into the election role.
func (v *VIPManager) Attach() {
	v.role.OnPromote(v.acquire)
	v.role.OnDemote(v.release)
}

// CleanupStale removes any leftover VIP interface from a previous (possibly
// crashed) run before election starts, so a restarting node never carries a
// stale VIP into the cluster. The leader re-acquires within a tick.
func (v *VIPManager) CleanupStale() {
	netdrv.StopDHCP(v.child)
	netdrv.DelLink(v.child)
}

func (v *VIPManager) acquire() {
	if v.parent == "" {
		log.Printf("vip: no mgmt interface configured (cluster.vip_iface) — skipping VIP")
		return
	}
	if err := netdrv.EnsureMacvlan(v.child, v.parent, v.mac); err != nil {
		log.Printf("vip: create macvlan %s on %s failed: %v", v.child, v.parent, err)
		return
	}
	netdrv.SetARPFlux(v.parent, v.child)

	if !v.dhcp {
		if v.static == "" {
			log.Printf("vip: vip_dhcp is false but no static cluster.vip set — skipping")
			return
		}
		if err := netdrv.AddAddr(v.child, v.static); err != nil {
			// Already present is fine (idempotent re-acquire).
			log.Printf("vip: add static %s on %s: %v (continuing)", v.static, v.child, err)
		}
		ip := strings.SplitN(v.static, "/", 2)[0]
		netdrv.GratuitousARP(v.child, ip)
		v.role.SetVIP(ip)
		log.Printf("vip: acquired static %s on %s", v.static, v.child)
		return
	}

	if err := netdrv.StartDHCP(v.child, v.clientID); err != nil {
		log.Printf("vip: dhcp on %s failed: %v", v.child, err)
		return
	}
	// Poll for the lease to land (dhcpcd backgrounds immediately).
	var ip string
	for i := 0; i < 30; i++ {
		if ip = netdrv.IfaceIPv4(v.child); ip != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if ip == "" {
		log.Printf("vip: dhcp lease not acquired on %s within timeout", v.child)
		return
	}
	netdrv.GratuitousARP(v.child, ip)
	v.role.SetVIP(ip)
	log.Printf("vip: acquired %s via DHCP on %s (mac %s)", ip, v.child, v.mac)
}

func (v *VIPManager) release() {
	if v.dhcp {
		netdrv.StopDHCP(v.child)
	} else if v.static != "" {
		netdrv.DelAddr(v.child, v.static)
	}
	netdrv.DelLink(v.child)
	v.role.SetVIP("")
	log.Printf("vip: released (%s torn down)", v.child)
}

// vipMAC derives a stable, locally-administered unicast MAC from the cluster
// secret. 0x02 first octet = locally administered + unicast.
func vipMAC(secret []byte) string {
	h := sha256.Sum256(append([]byte("vdxvip|"), secret...))
	b := []byte{0x02, h[0], h[1], h[2], h[3], h[4]}
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = hex.EncodeToString([]byte{x})
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
}
