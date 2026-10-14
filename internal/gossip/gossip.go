// Package gossip provides decentralized cluster membership with no central
// coordinator. Nodes discover each other over mDNS (zero-config) and/or static
// seeds, then maintain a shared view of who's alive and how much capacity each
// has via memberlist's SWIM gossip protocol. Each node advertises its live
// CPU/memory in its gossip metadata, so the scheduler can place a session on the
// least-loaded node from any node's point of view — there is no master.
package gossip

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	sockaddr "github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/mdns"
	"github.com/hashicorp/memberlist"
)

const mdnsService = "_vdxclone._tcp"

// Meta is the per-node payload gossiped in memberlist node metadata. It is kept
// small (well under memberlist's meta limit) and carries exactly what a remote
// node needs to schedule onto or migrate to this one.
type Meta struct {
	Name      string `json:"name"`
	Address   string `json:"addr"`     // routable host IP for SSH/migration
	CPUs      int    `json:"cpus"`
	MemFreeMB int64  `json:"mem_free"` // live free memory
	MemTotal  int64  `json:"mem_total"`
}

// Member is a resolved cluster peer (local or remote).
type Member struct {
	Meta
	Alive bool
}

// Config controls how this node joins the mesh.
type Config struct {
	NodeName   string
	BindAddr   string
	BindPort   int
	Seeds      []string // optional static "host:port" peers
	MDNS       bool     // enable mDNS discovery + advertisement
	Advertise  string   // routable address peers reach us at (for Meta.Address)
}

// Cluster is a running gossip membership handle.
type Cluster struct {
	ml   *memberlist.Memberlist
	del  *delegate
	cfg  Config
	srv  *mdns.Server
	stop chan struct{}
}

// delegate feeds this node's live Meta into gossip and keeps it fresh.
type delegate struct {
	mu   sync.RWMutex
	meta Meta
}

func (d *delegate) set(m Meta) { d.mu.Lock(); d.meta = m; d.mu.Unlock() }
func (d *delegate) get() Meta  { d.mu.RLock(); defer d.mu.RUnlock(); return d.meta }

func (d *delegate) NodeMeta(limit int) []byte {
	b, _ := json.Marshal(d.get())
	if len(b) > limit {
		return b[:limit]
	}
	return b
}
func (d *delegate) NotifyMsg([]byte)                           {}
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte { return nil }
func (d *delegate) LocalState(join bool) []byte                { return nil }
func (d *delegate) MergeRemoteState(buf []byte, join bool)     {}

// Start brings up gossip: creates the memberlist, advertises/discovers over
// mDNS, and joins any seeds or discovered peers. A single-node install forms a
// cluster of one and simply reports itself.
func Start(cfg Config) (*Cluster, error) {
	if cfg.Advertise == "" {
		if ip, err := sockaddr.GetPrivateIP(); err == nil {
			cfg.Advertise = ip
		}
	}
	del := &delegate{meta: Meta{Name: cfg.NodeName, Address: cfg.Advertise}}

	mlCfg := memberlist.DefaultLANConfig()
	mlCfg.Name = cfg.NodeName
	if cfg.BindAddr != "" {
		mlCfg.BindAddr = cfg.BindAddr
	}
	// BindPort 0 means "pick a free port" (memberlist updates the config to the
	// actual port after binding). A non-zero port is used verbatim.
	mlCfg.BindPort = cfg.BindPort
	mlCfg.AdvertisePort = cfg.BindPort
	mlCfg.Delegate = del
	mlCfg.LogOutput = logDiscard{}

	ml, err := memberlist.Create(mlCfg)
	if err != nil {
		return nil, fmt.Errorf("gossip create: %w", err)
	}
	// Reflect the actual bound port back (matters when BindPort was 0/random) so
	// mDNS advertises and self-filters on the real port.
	cfg.BindPort = mlCfg.BindPort
	c := &Cluster{ml: ml, del: del, cfg: cfg, stop: make(chan struct{})}

	if cfg.MDNS {
		if err := c.advertiseMDNS(); err != nil {
			log.Printf("gossip: mDNS advertise failed (continuing): %v", err)
		}
		go c.discoverLoop()
	}
	if len(cfg.Seeds) > 0 {
		if n, err := ml.Join(cfg.Seeds); err != nil {
			log.Printf("gossip: seed join reached %d peers, err=%v", n, err)
		}
	}
	return c, nil
}

// UpdateLocal refreshes this node's advertised capacity and re-broadcasts it.
func (c *Cluster) UpdateLocal(cpus int, memFreeMB, memTotalMB int64) {
	m := c.del.get()
	m.Name = c.cfg.NodeName
	if m.Address == "" {
		m.Address = c.cfg.Advertise
	}
	m.CPUs, m.MemFreeMB, m.MemTotal = cpus, memFreeMB, memTotalMB
	c.del.set(m)
	// Re-gossip the new metadata to peers.
	_ = c.ml.UpdateNode(2 * time.Second)
}

// Members returns the current cluster view decoded from gossiped metadata.
func (c *Cluster) Members() []Member {
	var out []Member
	for _, n := range c.ml.Members() {
		var meta Meta
		_ = json.Unmarshal(n.Meta, &meta)
		if meta.Name == "" {
			meta.Name = n.Name
		}
		if meta.Address == "" {
			meta.Address = n.Addr.String()
		}
		out = append(out, Member{Meta: meta, Alive: n.State == memberlist.StateAlive})
	}
	return out
}

// NumMembers reports the live member count (>=1: at least this node).
func (c *Cluster) NumMembers() int { return c.ml.NumMembers() }

// Shutdown leaves the cluster gracefully and tears down mDNS.
func (c *Cluster) Shutdown() {
	close(c.stop)
	if c.srv != nil {
		_ = c.srv.Shutdown()
	}
	_ = c.ml.Leave(2 * time.Second)
	_ = c.ml.Shutdown()
}

func (c *Cluster) advertiseMDNS() error {
	host, _ := memberlistHost(c.cfg.NodeName)
	var ips []net.IP
	if c.cfg.Advertise != "" {
		if ip := net.ParseIP(c.cfg.Advertise); ip != nil {
			ips = append(ips, ip)
		}
	}
	svc, err := mdns.NewMDNSService(host, mdnsService, "", "", c.cfg.BindPort, ips,
		[]string{"vdxclone node " + c.cfg.NodeName})
	if err != nil {
		return err
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: svc})
	if err != nil {
		return err
	}
	c.srv = srv
	return nil
}

// discoverLoop periodically browses mDNS for peers and joins any new ones.
func (c *Cluster) discoverLoop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	c.discoverOnce()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.discoverOnce()
		}
	}
}

func (c *Cluster) discoverOnce() {
	entries := make(chan *mdns.ServiceEntry, 8)
	go func() {
		var peers []string
		for e := range entries {
			if e.AddrV4 == nil || e.Port == 0 {
				continue
			}
			addr := fmt.Sprintf("%s:%d", e.AddrV4.String(), e.Port)
			// Skip ourselves.
			if e.Port == c.cfg.BindPort && (e.AddrV4.String() == c.cfg.Advertise) {
				continue
			}
			peers = append(peers, addr)
		}
		if len(peers) > 0 {
			_, _ = c.ml.Join(peers)
		}
	}()
	_ = mdns.Query(&mdns.QueryParam{
		Service:             mdnsService,
		Domain:              "local",
		Timeout:             3 * time.Second,
		Entries:             entries,
		WantUnicastResponse: true,
	})
	close(entries)
}

func memberlistHost(name string) (string, error) {
	if name != "" {
		return name, nil
	}
	return "vdxclone", nil
}

type logDiscard struct{}

func (logDiscard) Write(p []byte) (int, error) { return len(p), nil }
