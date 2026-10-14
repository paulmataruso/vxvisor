// Package web serves the browser UI. All data access goes through the service
// layer, which enforces authorization and writes audit events.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"strconv"

	"vdxclone/internal/config"
	"vdxclone/internal/oidc"
	"vdxclone/internal/service"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	cfg  *config.Config
	svc  *service.Service
	tmpl *template.Template
	oidc *oidc.Provider
}

// tmplFuncs are helpers available to every template.
var tmplFuncs = template.FuncMap{
	// humanBytes formats a byte count as B/KB/MB/GB/TB with sensible precision.
	"humanBytes": func(n int64) string {
		if n <= 0 {
			return "0 B"
		}
		units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
		f := float64(n)
		i := 0
		for f >= 1024 && i < len(units)-1 {
			f /= 1024
			i++
		}
		if i == 0 {
			return strconv.FormatInt(n, 10) + " B"
		}
		if f >= 100 {
			return strconv.FormatFloat(f, 'f', 0, 64) + " " + units[i]
		}
		return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
	},
}

func NewServer(cfg *config.Config, svc *service.Service) (*Server, error) {
	t, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, svc: svc, tmpl: t, oidc: oidc.New(cfg.OIDC)}, nil
}

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /oidc/login", s.oidcLogin)
	mux.HandleFunc("GET /oidc/callback", s.oidcCallback)

	mux.HandleFunc("GET /", s.auth(s.overview))
	mux.HandleFunc("GET /instances", s.auth(s.dashboard))
	// LXC system containers
	mux.HandleFunc("GET /containers", s.auth(s.containersPage))
	mux.HandleFunc("POST /containers", s.auth(s.createContainer))
	mux.HandleFunc("POST /containers/{id}/start", s.auth(s.startContainer))
	mux.HandleFunc("POST /containers/{id}/stop", s.auth(s.stopContainer))
	mux.HandleFunc("POST /containers/{id}/delete", s.auth(s.deleteContainer))
	mux.HandleFunc("POST /containers/{id}/snapshot", s.auth(s.snapshotContainer))
	mux.HandleFunc("POST /switch-org", s.auth(s.switchOrg))

	mux.HandleFunc("POST /sessions", s.auth(s.createSession))
	mux.HandleFunc("GET /instances/{id}", s.auth(s.instanceDetail))
	mux.HandleFunc("POST /sessions/{id}/start", s.auth(s.startSession))
	mux.HandleFunc("POST /sessions/{id}/stop", s.auth(s.stopSession))
	mux.HandleFunc("POST /sessions/{id}/resize", s.auth(s.resizeSession))
	mux.HandleFunc("POST /sessions/{id}/eject-iso", s.auth(s.ejectISO))
	mux.HandleFunc("POST /sessions/{id}/delete", s.auth(s.deleteSession))
	mux.HandleFunc("GET /console/{id}", s.auth(s.console))
	mux.HandleFunc("GET /console/{id}/ws", s.auth(s.vncProxy))
	// Full browser desktop via the guacd gateway (RDP with device redirection,
	// or VNC fallback). Separate route so the console page stays plugin-free noVNC.
	mux.HandleFunc("GET /desktop/{id}", s.auth(s.desktop))
	mux.HandleFunc("GET /desktop/{id}/ws", s.desktopProxy) // token- or cookie-authorized inside

	// M3: images & storage
	mux.HandleFunc("GET /isos", s.auth(s.isos))
	mux.HandleFunc("GET /api/isos", s.auth(s.apiISOs))
	mux.HandleFunc("POST /isos/upload", s.auth(s.uploadISO))
	mux.HandleFunc("POST /isos/pull", s.auth(s.pullISO))
	mux.HandleFunc("POST /isos/{id}/delete", s.auth(s.deleteISO))

	mux.HandleFunc("GET /templates", s.auth(s.templates))
	mux.HandleFunc("POST /templates", s.auth(s.createTemplate))
	mux.HandleFunc("POST /templates/{id}/delete", s.auth(s.deleteTemplate))
	mux.HandleFunc("POST /templates/{id}/launch", s.auth(s.launchTemplate))

	mux.HandleFunc("POST /sessions/{id}/snapshots", s.auth(s.createSnapshot))
	mux.HandleFunc("POST /sessions/{id}/snapshots/{sid}/revert", s.auth(s.revertSnapshot))
	mux.HandleFunc("POST /sessions/{id}/snapshots/{sid}/delete", s.auth(s.deleteSnapshot))
	mux.HandleFunc("POST /sessions/{id}/backup", s.auth(s.createBackup))
	mux.HandleFunc("POST /sessions/{id}/schedule", s.auth(s.createSchedule))
	mux.HandleFunc("POST /sessions/{id}/retention", s.auth(s.setRetention))

	mux.HandleFunc("GET /backups", s.auth(s.backups))
	mux.HandleFunc("POST /backups/{id}/restore", s.auth(s.restoreBackup))
	mux.HandleFunc("POST /backups/{id}/delete", s.auth(s.deleteBackup))
	mux.HandleFunc("POST /schedules/{id}/delete", s.auth(s.deleteSchedule))

	mux.HandleFunc("GET /storage", s.auth(s.storagePools))
	mux.HandleFunc("POST /storage", s.auth(s.upsertPool))
	mux.HandleFunc("POST /storage/delete", s.auth(s.deleteStoragePool))
	// ZFS + LVM pool management (admin; destructive ops confirmed in the UI).
	mux.HandleFunc("POST /storage/zfs/create", s.auth(s.createZFSPool))
	mux.HandleFunc("POST /storage/zfs/{name}/destroy", s.auth(s.destroyZFSPool))
	mux.HandleFunc("POST /storage/zfs/dataset", s.auth(s.createZFSDataset))
	mux.HandleFunc("POST /storage/zfs/replace", s.auth(s.replaceZFSDevice))
	mux.HandleFunc("POST /storage/zfs/cache", s.auth(s.addZFSCache))
	mux.HandleFunc("POST /storage/zfs/log", s.auth(s.addZFSLog))
	mux.HandleFunc("POST /storage/lvm/create", s.auth(s.createLVMPool))
	mux.HandleFunc("POST /storage/lvm/{vg}/remove", s.auth(s.removeVG))

	// Shared storage: dedicated storage NIC + NFS/CIFS/Ceph mounts + iSCSI.
	mux.HandleFunc("GET /shared", s.auth(s.sharedPage))
	mux.HandleFunc("POST /shared/iface", s.auth(s.setStorageIface))
	mux.HandleFunc("POST /shared/nfs", s.auth(s.addNFS))
	mux.HandleFunc("POST /shared/cifs", s.auth(s.addCIFS))
	mux.HandleFunc("POST /shared/ceph", s.auth(s.addCeph))
	mux.HandleFunc("POST /shared/{id}/unmount", s.auth(s.unmountShared))
	mux.HandleFunc("POST /shared/iscsi/login", s.auth(s.iscsiLogin))
	mux.HandleFunc("POST /shared/iscsi/{id}/logout", s.auth(s.iscsiLogout))
	mux.HandleFunc("GET /api/iscsi/discover", s.auth(s.apiISCSIDiscover))

	// Host-introspection JSON APIs (interface picker, disk picker, path
	// autocomplete, topology). Admin-gated inside the service.
	mux.HandleFunc("GET /api/interfaces", s.auth(s.apiInterfaces))
	mux.HandleFunc("GET /api/blockdevices", s.auth(s.apiBlockDevices))
	mux.HandleFunc("GET /api/fs", s.auth(s.apiFS))
	mux.HandleFunc("GET /api/topology", s.auth(s.apiTopology))

	// L3 routing (FRR static/OSPF/BGP + nftables NAT/firewall) — button-driven CRUD.
	mux.HandleFunc("GET /routing", s.auth(s.routingPage))
	mux.HandleFunc("POST /routing/apply", s.auth(s.applyRouting))
	mux.HandleFunc("POST /routing/uplink", s.auth(s.rtSetUplink))
	mux.HandleFunc("POST /routing/static", s.auth(s.rtAddStatic))
	mux.HandleFunc("POST /routing/static/{i}/delete", s.auth(s.rtDelStatic))
	mux.HandleFunc("POST /routing/firewall", s.auth(s.rtAddFirewall))
	mux.HandleFunc("POST /routing/firewall/{i}/delete", s.auth(s.rtDelFirewall))
	mux.HandleFunc("POST /routing/prefix", s.auth(s.rtAddPrefix))
	mux.HandleFunc("POST /routing/prefix/{i}/delete", s.auth(s.rtDelPrefix))
	mux.HandleFunc("POST /routing/prefixlist", s.auth(s.rtAddPrefixList))
	mux.HandleFunc("POST /routing/prefixlist/{i}/delete", s.auth(s.rtDelPrefixList))
	mux.HandleFunc("POST /routing/routemap", s.auth(s.rtAddRouteMap))
	mux.HandleFunc("POST /routing/routemap/{i}/delete", s.auth(s.rtDelRouteMap))
	mux.HandleFunc("POST /routing/ospf", s.auth(s.rtSetOSPF))
	mux.HandleFunc("POST /routing/ospf/net", s.auth(s.rtAddOSPFNet))
	mux.HandleFunc("POST /routing/ospf/net/{i}/delete", s.auth(s.rtDelOSPFNet))
	mux.HandleFunc("POST /routing/bgp", s.auth(s.rtSetBGP))
	mux.HandleFunc("POST /routing/bgp/neighbor", s.auth(s.rtAddBGPNeighbor))
	mux.HandleFunc("POST /routing/bgp/neighbor/{i}/delete", s.auth(s.rtDelBGPNeighbor))
	mux.HandleFunc("POST /routing/bgp/network", s.auth(s.rtAddBGPNetwork))
	mux.HandleFunc("POST /routing/bgp/network/{i}/delete", s.auth(s.rtDelBGPNetwork))

	// M4: networking
	mux.HandleFunc("GET /networks", s.auth(s.networks))
	mux.HandleFunc("POST /networks", s.auth(s.createNetwork))
	mux.HandleFunc("POST /networks/{id}/delete", s.auth(s.deleteNetwork))
	// VMware-style data plane: bonds (LACP/etherchannel) + vSwitches (VLAN trunks).
	mux.HandleFunc("POST /networks/bonds", s.auth(s.createBond))
	mux.HandleFunc("POST /networks/bonds/{name}/delete", s.auth(s.deleteBond))
	mux.HandleFunc("POST /networks/vswitches", s.auth(s.createVSwitch))
	mux.HandleFunc("POST /networks/vswitches/{name}/delete", s.auth(s.deleteVSwitch))
	mux.HandleFunc("POST /sessions/{id}/forwards", s.auth(s.addPortForward))
	mux.HandleFunc("POST /sessions/{id}/forwards/{pfid}/delete", s.auth(s.deletePortForward))

	// M5: observability
	mux.HandleFunc("GET /observability", s.auth(s.observability))
	mux.HandleFunc("GET /observability/ws", s.auth(s.metricsWS))
	mux.HandleFunc("GET /api/metrics/history", s.auth(s.apiMetricsHistory))
	mux.HandleFunc("POST /alert-rules", s.auth(s.createAlertRule))
	mux.HandleFunc("POST /alert-rules/{id}/delete", s.auth(s.deleteAlertRule))
	mux.HandleFunc("POST /alert-channels", s.auth(s.createAlertChannel))

	// M6: billing, quotas, trash
	mux.HandleFunc("GET /billing", s.auth(s.billing))
	mux.HandleFunc("POST /billing/quota", s.auth(s.setQuota))
	mux.HandleFunc("GET /trash", s.auth(s.trash))
	mux.HandleFunc("POST /trash/{id}/restore", s.auth(s.restoreSession))
	mux.HandleFunc("POST /trash/{id}/purge", s.auth(s.purgeSession))

	// M7: cluster
	mux.HandleFunc("GET /cluster", s.auth(s.cluster))
	mux.HandleFunc("POST /cluster/nodes", s.auth(s.addNode))
	mux.HandleFunc("POST /cluster/nodes/{id}/probe", s.auth(s.probeNode))
	mux.HandleFunc("POST /cluster/nodes/{id}/delete", s.auth(s.deleteNode))
	mux.HandleFunc("POST /cluster/import", s.auth(s.importImage))
	mux.HandleFunc("POST /sessions/{id}/migrate", s.auth(s.migrateSession))

	// VDI broker: desktop pool administration (admin creates pools + grants).
	mux.HandleFunc("GET /pools", s.auth(s.adminPools))
	mux.HandleFunc("POST /pools", s.auth(s.createPool))
	mux.HandleFunc("POST /pools/{id}/delete", s.auth(s.deletePool))
	mux.HandleFunc("POST /pools/{id}/grant", s.auth(s.grantPool))

	mux.HandleFunc("GET /members", s.auth(s.members))
	mux.HandleFunc("POST /members/add", s.auth(s.addMember))
	mux.HandleFunc("POST /members/{uid}/remove", s.auth(s.removeMember))

	mux.HandleFunc("GET /apikeys", s.auth(s.apiKeys))
	mux.HandleFunc("POST /apikeys/create", s.auth(s.createAPIKey))
	mux.HandleFunc("POST /apikeys/{id}/revoke", s.auth(s.revokeAPIKey))

	mux.HandleFunc("GET /orgs", s.auth(s.orgs))
	mux.HandleFunc("POST /orgs", s.auth(s.createOrg))
	mux.HandleFunc("GET /audit", s.auth(s.audit))

	mux.Handle("GET /static/", http.FileServerFS(staticFS))
}

// auth resolves the principal and passes it to the handler, redirecting to the
// login page when unauthenticated.
func (s *Server) auth(h func(http.ResponseWriter, *http.Request, *service.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.svc.Principal(r)
		if p == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r, p)
	}
}

// ---- CSRF ----------------------------------------------------------------
//
// Synchronizer token bound to the session cookie: the token is derived from the
// (httpOnly, unreadable to JS) session token, so a cross-site attacker cannot
// produce it. Every mutating form carries it; POST handlers verify it.

func csrfToken(sessionToken string) string {
	sum := sha256.Sum256([]byte("csrf:" + sessionToken))
	return hex.EncodeToString(sum[:16])
}

func (s *Server) checkCSRF(p *service.Principal, r *http.Request) bool {
	return r.FormValue("csrf") == csrfToken(p.Token())
}

func (s *Server) badCSRF(w http.ResponseWriter) { http.Error(w, "bad csrf token", http.StatusForbidden) }

// ---- rendering -----------------------------------------------------------

func (s *Server) render(w http.ResponseWriter, p *service.Principal, name, active string, data map[string]any) {
	view := map[string]any{
		"P":         p,
		"CSRF":      csrfToken(p.Token()),
		"Active":    active,
		"PortalURL": s.portalURL(),
	}
	for k, v := range data {
		view[k] = v
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	if err := s.tmpl.ExecuteTemplate(w, name, view); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

// portalURL is the public VDI portal's address for the admin "VDI Portal" link.
// Prefers the configured public base URL; otherwise derives one from the public
// listener address. Empty when the portal is disabled.
func (s *Server) portalURL() string {
	if !s.cfg.Public.Enabled {
		return ""
	}
	if s.cfg.Public.BaseURL != "" {
		return s.cfg.Public.BaseURL
	}
	if s.cfg.Public.Addr != "" {
		host := s.cfg.Public.Addr
		if h, _, err := net.SplitHostPort(host); err == nil && (h == "" || h == "0.0.0.0") {
			return "" // wildcard bind — no single reachable URL to link
		}
		return "http://" + s.cfg.Public.Addr
	}
	return ""
}

// writeJSON sends v as an application/json response. It is the one JSON helper
// for the AJAX endpoints (interface picker, disk picker, path autocomplete,
// topology). Errors after the header are unrecoverable, so it logs none.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func atoi(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
