// Command vdxd is the VXVisor daemon and CLI.
//
// Subcommands:
//   vdxd serve                       run the web UI + REST API
//   vdxd user add <name> [--admin]   create a user (prompts for password)
//   vdxd org add <name> <slug>       create an org
//   vdxd image pull <name>           download a base image into the cache
//   vdxd version
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"vdxclone/internal/api"
	"vdxclone/internal/auth"
	"vdxclone/internal/broker"
	"vdxclone/internal/cluster"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/gossip"
	"vdxclone/internal/image"
	"vdxclone/internal/license"
	"vdxclone/internal/metrics"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/peer"
	"vdxclone/internal/platform"
	"vdxclone/internal/policy"
	"vdxclone/internal/qemu"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
	"vdxclone/internal/storage"
	"vdxclone/internal/store"
	"vdxclone/internal/web"
	"vdxclone/internal/worker"
)

var version = "0.1.0-dev"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	cfgPath := os.Getenv("VDX_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/vdxclone/config.toml"
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(cfgPath)
	case "user":
		cmdUser(cfgPath, os.Args[2:])
	case "org":
		cmdOrg(cfgPath, os.Args[2:])
	case "image":
		cmdImage(cfgPath, os.Args[2:])
	case "import":
		cmdImport(cfgPath, os.Args[2:])
	case "self-update":
		cmdSelfUpdate(cfgPath)
	case "migrate-recv":
		cmdMigrateRecv(cfgPath, os.Args[2:])
	case "license":
		cmdLicense(cfgPath, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("vdxd", version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vdxd <serve|user add <name> [--admin]|org add <name> <slug>|org member <slug> <user> <role>|image pull <name>|import <name> <file>|self-update|license <sign|show> <file> --key K|version>")
	os.Exit(2)
}

func open(cfgPath string) (*config.Config, *db.DB) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := cfg.EnsureDirs(); err != nil {
		log.Fatalf("mkdirs: %v", err)
	}
	d, err := db.OpenResilient(cfg.DBPath(), cfg.Paths.BackupDir)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	// Take a verified snapshot at boot and prune to a rolling set, so there is
	// always a recent known-good backup to self-heal from.
	if bak, err := d.Backup(cfg.Paths.BackupDir); err != nil {
		log.Printf("db: startup backup skipped: %v", err)
	} else if bak != "" {
		db.PruneBackups(cfg.Paths.BackupDir, 24)
	}
	return cfg, d
}

func cmdServe(cfgPath string) {
	cfg, d := open(cfgPath)
	st := store.New(d)
	stg := storage.New(cfg, d)
	net := netdrv.New(d)
	mgr := session.NewManager(cfg, d)
	mc := metrics.NewCollector(d, cfg.Paths.DiskDir)
	cl := cluster.New(d)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "control"
	}
	nodeName := hostname
	if cfg.Cluster.NodeName != "" {
		nodeName = cfg.Cluster.NodeName
	}
	cl.EnsureLocalNode(nodeName)

	// Cluster networking: bring up the VM bridge, and the VXLAN overlay that
	// stitches every node's bridge into one L2 segment (so a migrated guest
	// keeps its IP). Only when the operator opts into bridge/overlay networking.
	if cfg.Network.Mode == "bridge" || cfg.Network.Mode == "overlay" {
		if cfg.Cluster.Overlay {
			oc := overlayConfig(cfg)
			if err := netdrv.EnsureOverlay(oc); err != nil {
				log.Printf("overlay setup failed (continuing in bridge-only mode): %v", err)
				_ = netdrv.EnsureBridge(cfg.Cluster.Bridge)
			} else {
				log.Printf("VXLAN overlay up: bridge=%s vni=%d underlay=%s", oc.Bridge, oc.VNI, oc.Underlay)
			}
		} else if err := netdrv.EnsureBridge(cfg.Cluster.Bridge); err != nil {
			log.Printf("bridge setup failed: %v", err)
		}
	}

	// Decentralized membership: discover peers over mDNS and/or seeds and gossip
	// live capacity. No central coordinator — every node holds the same view. In
	// cluster mode gossip is always on (seeds required) and authenticated with the
	// shared cluster secret, because leadership — and thus VIP ownership — rides it.
	var gc *gossip.Cluster
	var role *cluster.Role
	var clusterSecret []byte
	clusterMode := cfg.Cluster.Enabled
	mgmtAddr := cfg.Cluster.MgmtAddr
	if clusterMode && mgmtAddr == "" {
		mgmtAddr = defaultSrcIP()
	}
	if clusterMode {
		sk, err := broker.LoadOrCreateSecret(cfg.ClusterSecretPath())
		if err != nil {
			log.Fatalf("cluster secret %s: %v", cfg.ClusterSecretPath(), err)
		}
		clusterSecret = sk
	}
	if clusterMode || cfg.Cluster.MDNS || len(cfg.Cluster.Seeds) > 0 {
		g, err := gossip.Start(gossip.Config{
			NodeName:  nodeName,
			BindAddr:  cfg.Cluster.GossipBind,
			BindPort:  cfg.Cluster.GossipPort,
			Seeds:     cfg.Cluster.Seeds,
			MDNS:      cfg.Cluster.MDNS,
			Advertise: cfg.Cluster.Advertise,
			MgmtAddr:  mgmtAddr,
			Primary:   cfg.Cluster.Primary,
			SecretKey: clusterSecret,
		})
		if err != nil {
			log.Printf("gossip disabled: %v", err)
		} else {
			gc = g
			defer gc.Shutdown()
			log.Printf("gossip up: node=%s members=%d (cluster mode=%v, primary=%v)", nodeName, gc.NumMembers(), clusterMode, cfg.Cluster.Primary)
		}
	}

	// Cluster mode: leader election + floating management VIP. Exactly one node
	// holds the lease and owns the VIP (single pane of glass); every node still
	// runs its own VMs (active/active).
	clusterStop := make(chan struct{})
	if clusterMode && gc != nil {
		role = cluster.NewRole(gc, nodeName, cfg.Cluster.Primary, cfg.ClusterAdminPort())
		vipm := cluster.NewVIPManager(role, clusterSecret, cfg.Cluster.VIPIface, cfg.Cluster.VIP, cfg.Cluster.VIPDHCP)
		vipm.CleanupStale() // drop any VIP left over from a crashed previous run
		vipm.Attach()
		go role.Run(clusterStop)
		defer close(clusterStop)
		log.Printf("cluster: election running (vip_iface=%s dhcp=%v)", cfg.Cluster.VIPIface, cfg.Cluster.VIPDHCP)
	}

	// Enforcer selection: licensing is OFF by default (NoopEnforcer, no network).
	// When the operator enables it, load and verify the offline signed license.
	var enf policy.Enforcer = policy.NoopEnforcer{}
	if cfg.License.Enabled {
		lic, err := license.Load(cfg.License.File, cfg.License.Key)
		if err != nil {
			log.Fatalf("license: %v", err)
		}
		enf = license.NewEnforcer(lic)
		log.Printf("license enforcement ON: licensee=%q seats=%d servers=%d", lic.Licensee, lic.Seats, lic.Servers)
	}
	svc := service.New(cfg, d, st, stg, net, mgr, enf)
	svc.SetMetrics(mc)
	svc.SetCluster(cl)
	if clusterMode && role != nil {
		svc.SetClusterRuntime(role, clusterSecret)
		cl.SetPeerClient(peer.NewClient(clusterSecret))
	}

	// VDI broker: desktop pools + per-connection tokens. The token secret is a
	// key file under the data dir (created on first run); never hardcoded.
	secretPath := cfg.Broker.SecretFile
	if secretPath == "" {
		secretPath = filepath.Join(cfg.Paths.DataDir, "broker.key")
	}
	if secret, err := broker.LoadOrCreateSecret(secretPath); err != nil {
		log.Printf("broker token secret unavailable (VDI portal disabled): %v", err)
	} else {
		svc.SetBroker(broker.NewPoolStore(d), broker.NewSigner(secret))
	}

	srv, err := web.NewServer(cfg, svc)
	if err != nil {
		log.Fatalf("web: %v", err)
	}
	mux := http.NewServeMux()
	srv.Routes(mux)
	api.New(svc).Routes(mux)

	// Node-to-node cluster API on a SEPARATE listener bound to the cluster NIC
	// only (HMAC-authenticated with the shared secret): aggregation, lifecycle
	// proxying, console relay, and account sync between peers.
	var peerSrv *http.Server
	if clusterMode && role != nil {
		srv.SetClusterPeer(clusterSecret)
		pmux := http.NewServeMux()
		srv.PeerRoutes(pmux)
		addr := cfg.Cluster.APIAddr
		if addr == "" {
			host := cfg.Cluster.Advertise
			if host == "" {
				host = "0.0.0.0"
			}
			addr = fmt.Sprintf("%s:%d", host, service.ClusterAPIPort)
		}
		peerSrv = &http.Server{Addr: addr, Handler: pmux}
		go func() {
			log.Printf("vdxd cluster peer API listening on %s", addr)
			if err := peerSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("peer API listener error: %v", err)
			}
		}()
	}

	// Background workers (reconciler, session GC).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sup := worker.New(cfg, d, mgr, stg, mc, cl)
	sup.SetGossip(gc)
	sup.SetService(svc)
	sup.SetRole(role)
	go sup.Run(ctx)

	httpSrv := &http.Server{Addr: cfg.Server.Addr, Handler: logReq(mux)}
	go func() {
		log.Printf("vdxd %s listening on %s (network mode: %s, kvm: %v)",
			version, cfg.Server.Addr, cfg.Network.Mode, kvmStr())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Public VDI portal on a SEPARATE listener (admin screens are not served
	// here). Put a TLS-terminating reverse proxy in front; bind to loopback.
	var publicSrv *http.Server
	if cfg.Public.Enabled && svc.BrokerReady() {
		pmux := http.NewServeMux()
		srv.PublicRoutes(pmux)
		addr := cfg.Public.Addr
		if addr == "" {
			addr = "127.0.0.1:8768"
		}
		publicSrv = &http.Server{Addr: addr, Handler: logReq(pmux)}
		go func() {
			log.Printf("vdxd public VDI portal listening on %s (front with a TLS proxy)", addr)
			if err := publicSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("public listener error: %v", err)
			}
		}()
	}

	<-ctx.Done()
	log.Println("shutting down…")
	// Release the VIP synchronously BEFORE exit so the macvlan is gone and no
	// stale dual-VIP lingers. Closing clusterStop alone races the process exit.
	if role != nil {
		role.Shutdown()
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	if publicSrv != nil {
		_ = publicSrv.Shutdown(shutCtx)
	}
	if peerSrv != nil {
		_ = peerSrv.Shutdown(shutCtx)
	}
}

func cmdUser(cfgPath string, args []string) {
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	admin := fs.Bool("admin", false, "create as admin")
	if len(args) < 2 || args[0] != "add" {
		log.Fatal("usage: vdxd user add <name> [--admin]")
	}
	name := args[1]
	_ = fs.Parse(args[2:])

	_, d := open(cfgPath)
	role := "user"
	if *admin {
		role = "admin"
	}
	pw := prompt("Password for " + name + ": ")
	if err := auth.CreateUser(d, name, pw, role); err != nil {
		log.Fatalf("create user: %v", err)
	}
	fmt.Printf("created %s (%s)\n", name, role)
}

func cmdOrg(cfgPath string, args []string) {
	switch {
	case len(args) >= 3 && args[0] == "add":
		_, d := open(cfgPath)
		st := store.New(d)
		id, err := st.CreateOrg(args[1], args[2])
		if err != nil {
			log.Fatalf("create org: %v", err)
		}
		fmt.Printf("created org %q (slug=%s, id=%d)\n", args[1], args[2], id)
	case len(args) >= 4 && args[0] == "member":
		// vdxd org member <slug> <username> <role>
		_, d := open(cfgPath)
		st := store.New(d)
		org, err := st.OrgBySlug(args[1])
		if err != nil {
			log.Fatalf("no such org %q", args[1])
		}
		uid, err := st.UserIDByName(args[2])
		if err != nil {
			log.Fatalf("no such user %q", args[2])
		}
		if err := st.AddMember(org.ID, uid, args[3]); err != nil {
			log.Fatalf("add member: %v", err)
		}
		fmt.Printf("added %s to %s as %s\n", args[2], args[1], args[3])
	default:
		log.Fatal("usage: vdxd org add <name> <slug>  |  vdxd org member <slug> <username> <role>")
	}
}

func cmdImage(cfgPath string, args []string) {
	if len(args) < 2 || args[0] != "pull" {
		log.Fatal("usage: vdxd image pull <name>  (e.g. ubuntu-24.04)")
	}
	cfg, d := open(cfgPath)
	name := args[1]
	fmt.Printf("pulling %s …\n", name)
	if err := image.Pull(cfg, d, name); err != nil {
		log.Fatalf("pull: %v", err)
	}
	fmt.Printf("image %s ready\n", name)
}

func cmdImport(cfgPath string, args []string) {
	if len(args) < 2 {
		log.Fatal("usage: vdxd import <image-name> <disk-file>  (VMDK/VHD/raw → qcow2)")
	}
	cfg, d := open(cfgPath)
	fmt.Printf("importing %s → image %q …\n", args[1], args[0])
	img, err := platform.ImportDisk(cfg, d, args[0], args[1])
	if err != nil {
		log.Fatalf("import: %v", err)
	}
	fmt.Printf("imported as base image %q (ready)\n", img)
}

func cmdSelfUpdate(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	rel, err := platform.CheckUpdate(cfg.Update.FeedURL)
	if err != nil {
		log.Fatalf("check update: %v", err)
	}
	if rel.Version == version {
		fmt.Printf("already up to date (%s)\n", version)
		return
	}
	self, err := os.Executable()
	if err != nil {
		log.Fatalf("locate binary: %v", err)
	}
	fmt.Printf("updating %s → %s …\n", version, rel.Version)
	if err := platform.ApplyUpdate(rel, self); err != nil {
		log.Fatalf("apply update: %v", err)
	}
	fmt.Printf("updated to %s. Restart the service (e.g. systemctl restart vdxd). Previous binary kept at %s.bak\n", rel.Version, self)
}

func cmdLicense(cfgPath string, args []string) {
	// vdxd license sign <out.json> --key K --licensee NAME --seats N --servers N --storage N [--expires RFC3339]
	// vdxd license show <file.json> --key K
	if len(args) < 2 {
		log.Fatal("usage: vdxd license <sign|show> <file> [flags]")
	}
	sub, file := args[0], args[1]
	fs := flag.NewFlagSet("license", flag.ExitOnError)
	key := fs.String("key", "", "symmetric signing key")
	licensee := fs.String("licensee", "local", "licensee name")
	seats := fs.Int("seats", 0, "max running sessions (0=unlimited)")
	servers := fs.Int("servers", 0, "max server VMs")
	storage := fs.Int("storage", 0, "max storage GB")
	plan := fs.String("plan", "local", "plan name")
	expires := fs.String("expires", "", "expiry RFC3339 (empty=perpetual)")
	_ = fs.Parse(args[2:])
	if *key == "" {
		log.Fatal("--key is required")
	}
	switch sub {
	case "sign":
		p := license.Payload{
			Licensee: *licensee, Seats: *seats, Servers: *servers, StorageGB: *storage,
			Plan: *plan, IssuedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: *expires,
		}
		f, err := license.Sign(p, *key)
		if err != nil {
			log.Fatalf("sign: %v", err)
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile(file, b, 0o600); err != nil {
			log.Fatalf("write: %v", err)
		}
		fmt.Printf("wrote signed license %s (seats=%d servers=%d)\n", file, *seats, *servers)
	case "show":
		p, err := license.Load(file, *key)
		if err != nil {
			log.Fatalf("verify: %v", err)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Printf("valid license:\n%s\n", b)
	default:
		log.Fatal("usage: vdxd license <sign|show> <file> [flags]")
	}
}

// overlayConfig derives the netdrv overlay parameters from the cluster config.
func overlayConfig(cfg *config.Config) netdrv.OverlayConfig {
	prefix := 16
	if i := strings.LastIndex(cfg.Cluster.Subnet, "/"); i >= 0 {
		if n, err := strconv.Atoi(cfg.Cluster.Subnet[i+1:]); err == nil {
			prefix = n
		}
	}
	return netdrv.OverlayConfig{
		Bridge:      cfg.Cluster.Bridge,
		VNI:         cfg.Cluster.VNI,
		Underlay:    cfg.Cluster.Underlay,
		Gateway:     cfg.Cluster.Gateway,
		GatewayCIDR: prefix,
	}
}

// cmdMigrateRecv launches a QEMU on this (destination) node ready to receive an
// inbound live migration. It is invoked over SSH by the source node's migration
// orchestrator with a base64-encoded qemu.Spec whose Incoming field is set.
func cmdMigrateRecv(cfgPath string, args []string) {
	if len(args) < 2 {
		log.Fatal("usage: vdxd migrate-recv <port> <base64-spec>")
	}
	cfg, _ := open(cfgPath)
	blob, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		log.Fatalf("decode spec: %v", err)
	}
	var spec qemu.Spec
	if err := json.Unmarshal(blob, &spec); err != nil {
		log.Fatalf("unmarshal spec: %v", err)
	}
	spec.Incoming = "tcp:0.0.0.0:" + args[0]
	logPath := qemu.LogPath(cfg.Paths.DiskDir, "recv-"+spec.ID)
	proc, err := qemu.Launch(spec, logPath)
	if err != nil {
		log.Fatalf("launch receiver: %v", err)
	}
	fmt.Printf("migration receiver up (pid=%d) awaiting stream on port %s\n", proc.Pid, args[0])
}

func prompt(label string) string {
	fmt.Print(label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return strings.TrimSpace(string(b))
	}
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}

func kvmStr() bool {
	_, err := os.Stat("/dev/kvm")
	return err == nil
}

// defaultSrcIP returns the source IP the kernel uses to reach the default route
// (the mgmt NIC's address), used as the VIP-probe target when not configured.
func defaultSrcIP() string {
	out, err := exec.Command("sh", "-c",
		`ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'`).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func logReq(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}
