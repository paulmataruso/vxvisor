// Package web serves the browser UI. All data access goes through the service
// layer, which enforces authorization and writes audit events.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/config"
	"vdxclone/internal/ad"
	"vdxclone/internal/oidc"
	"vdxclone/internal/peer"
	"vdxclone/internal/service"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	cfg         *config.Config
	svc         *service.Service
	tmpl        *template.Template
	oidc        *oidc.Provider
	ad          *ad.Provider
	clusterAuth *peer.Auth
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
	// dict builds a map from alternating key/value pairs, so a template can pass
	// several named values to a sub-template (html/template has no native way).
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, fmt.Errorf("dict needs an even number of arguments")
		}
		m := make(map[string]any, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict keys must be strings")
			}
			m[k] = kv[i+1]
		}
		return m, nil
	},
}

func NewServer(cfg *config.Config, svc *service.Service) (*Server, error) {
	t, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, svc: svc, tmpl: t, oidc: oidc.New(cfg.OIDC), ad: ad.New(cfg.AD)}
	// Apply the DB-persisted AD settings (Settings → Authentication) over the TOML
	// [ad] default, so GUI-managed config is live from boot. Falls back to cfg.AD
	// when nothing has been saved.
	srv.ad.SetConfig(svc.ADConfig())
	// Register the live-reload hook so a save here — or a replicated snapshot on a
	// cluster follower — updates the auth provider without a restart.
	svc.SetADReloadHook(srv.ad.SetConfig)
	return srv, nil
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
	mux.HandleFunc("POST /containers/{id}/update", s.auth(s.updateContainer))
	mux.HandleFunc("POST /containers/{id}/stop", s.auth(s.stopContainer))
	mux.HandleFunc("POST /containers/{id}/delete", s.auth(s.deleteContainer))
	mux.HandleFunc("POST /containers/{id}/snapshot", s.auth(s.snapshotContainer))
	mux.HandleFunc("GET /containers/{id}/console", s.auth(s.containerConsole))
	mux.HandleFunc("GET /containers/{id}/console/ws", s.auth(s.containerConsoleWS))
	mux.HandleFunc("POST /switch-org", s.auth(s.switchOrg))

	mux.HandleFunc("POST /sessions", s.auth(s.createSession))
	// Inventory folders (VMware-style tree on the instances page). Mutations
	// support drag-and-drop (?ajax=1 → JSON) and a plain form POST fallback.
	mux.HandleFunc("POST /folders", s.auth(s.folderCreate))
	mux.HandleFunc("POST /folders/{id}/rename", s.auth(s.folderRename))
	mux.HandleFunc("POST /folders/{id}/delete", s.auth(s.folderDelete))
	mux.HandleFunc("POST /folders/{id}/move", s.auth(s.folderMove))
	mux.HandleFunc("POST /folders/move-vm", s.auth(s.folderMoveVM))
	// VM-scoped admin routes are cluster-transparent: on the VIP a request for a
	// VM owned by another node is reverse-proxied to that node (vmManage), so full
	// per-VM management works from the unified view and from each host's own IP.
	mux.HandleFunc("GET /instances/{id}", s.auth(s.vmManage(s.instanceDetail)))
	mux.HandleFunc("POST /sessions/{id}/start", s.auth(s.vmManage(s.startSession)))
	mux.HandleFunc("POST /sessions/{id}/stop", s.auth(s.vmManage(s.stopSession)))
	mux.HandleFunc("POST /sessions/{id}/restart", s.auth(s.vmManage(s.restartSession)))
	mux.HandleFunc("POST /sessions/{id}/autostart", s.auth(s.vmManage(s.autostartSession)))
	mux.HandleFunc("POST /sessions/{id}/resize", s.auth(s.vmManage(s.resizeSession)))
	mux.HandleFunc("POST /sessions/{id}/spec", s.auth(s.vmManage(s.updateSessionSpec)))
	mux.HandleFunc("POST /sessions/{id}/network", s.auth(s.vmManage(s.setSessionNetwork)))
	mux.HandleFunc("POST /sessions/{id}/spec-field", s.auth(s.vmManage(s.setSpecField)))
	mux.HandleFunc("POST /sessions/{id}/eject-iso", s.auth(s.vmManage(s.ejectISO)))
	mux.HandleFunc("POST /sessions/{id}/eject-virtio", s.auth(s.vmManage(s.ejectVirtio)))
	mux.HandleFunc("POST /sessions/{id}/mount-virtio", s.auth(s.vmManage(s.mountVirtio)))
	mux.HandleFunc("POST /sessions/{id}/delete", s.auth(s.vmManage(s.deleteSession)))
	mux.HandleFunc("GET /console/{id}", s.auth(s.console))
	mux.HandleFunc("GET /console/{id}/ws", s.auth(s.vncProxy))
	mux.HandleFunc("GET /console/{id}/serial", s.auth(s.serialConsole))
	mux.HandleFunc("GET /console/{id}/serial/ws", s.auth(s.serialProxy))

	// M3: images & storage
	mux.HandleFunc("GET /clients", s.auth(s.clientsPage))
	// Public (no auth): the desktop shell self-updates before the user logs in, so
	// it must read the latest-client metadata and download the binary without a
	// session. The binaries are distributed to users anyway (not secret); both
	// handlers ignore the principal. The /clients browser page stays authed.
	mux.HandleFunc("GET /clients/latest", func(w http.ResponseWriter, r *http.Request) { s.clientLatest(w, r, nil) })
	mux.HandleFunc("GET /clients/download/{name}", func(w http.ResponseWriter, r *http.Request) { s.clientDownload(w, r, nil) })
	mux.HandleFunc("GET /update", s.auth(s.updatePage))
	mux.HandleFunc("POST /update/check", s.auth(s.updateCheck))
	mux.HandleFunc("POST /update/apply", s.auth(s.updateApply))
	mux.HandleFunc("POST /update/channel", s.auth(s.updateChannel))

	mux.HandleFunc("GET /isos", s.auth(s.isos))
	mux.HandleFunc("GET /api/isos", s.auth(s.apiISOs))
	mux.HandleFunc("POST /isos/upload", s.auth(s.uploadISO))
	mux.HandleFunc("POST /isos/pull", s.auth(s.pullISO))
	mux.HandleFunc("POST /isos/{id}/delete", s.auth(s.deleteISO))

	mux.HandleFunc("GET /templates", s.auth(s.templates))
	mux.HandleFunc("POST /templates", s.auth(s.createTemplate))
	mux.HandleFunc("POST /templates/{id}/delete", s.auth(s.deleteTemplate))
	mux.HandleFunc("POST /templates/{id}/launch", s.auth(s.launchTemplate))

	mux.HandleFunc("POST /sessions/{id}/snapshots", s.auth(s.vmManage(s.createSnapshot)))
	mux.HandleFunc("POST /sessions/{id}/snapshots/{sid}/revert", s.auth(s.vmManage(s.revertSnapshot)))
	mux.HandleFunc("POST /sessions/{id}/snapshots/{sid}/delete", s.auth(s.vmManage(s.deleteSnapshot)))
	mux.HandleFunc("POST /sessions/{id}/backup", s.auth(s.vmManage(s.createBackup)))
	mux.HandleFunc("POST /sessions/{id}/schedule", s.auth(s.vmManage(s.createSchedule)))
	mux.HandleFunc("POST /sessions/{id}/retention", s.auth(s.vmManage(s.setRetention)))

	mux.HandleFunc("GET /backups", s.auth(s.backups))
	mux.HandleFunc("POST /backups/create", s.auth(s.createBackup))
	mux.HandleFunc("POST /schedules/create", s.auth(s.createSchedule))
	mux.HandleFunc("POST /backups/targets", s.auth(s.createBackupTarget))
	mux.HandleFunc("POST /backups/targets/{id}/delete", s.auth(s.deleteBackupTarget))
	mux.HandleFunc("POST /backups/targets/{id}/test", s.auth(s.testBackupTarget))
	mux.HandleFunc("POST /backups/{id}/restore", s.auth(s.restoreBackup))
	mux.HandleFunc("POST /backups/{id}/delete", s.auth(s.deleteBackup))
	mux.HandleFunc("POST /schedules/{id}/delete", s.auth(s.deleteSchedule))

	mux.HandleFunc("GET /storage", s.auth(s.storagePools))
	mux.HandleFunc("GET /api/storage/pool/{id}/browse", s.auth(s.apiBrowsePool))
	mux.HandleFunc("POST /storage/vddk-libdir", s.auth(s.setVDDKLibDir))
	mux.HandleFunc("POST /cluster/vddk-upload", s.auth(s.uploadVDDK))
	mux.HandleFunc("POST /storage", s.auth(s.upsertPool))
	mux.HandleFunc("POST /storage/delete", s.auth(s.deleteStoragePool))
	mux.HandleFunc("POST /storage/disk/wipe", s.auth(s.wipeDisk))
	// ZFS + LVM pool management (admin; destructive ops confirmed in the UI).
	mux.HandleFunc("POST /storage/zfs/create", s.auth(s.createZFSPool))
	mux.HandleFunc("POST /storage/zfs/{name}/destroy", s.auth(s.destroyZFSPool))
	mux.HandleFunc("POST /storage/zfs/dataset", s.auth(s.createZFSDataset))
	mux.HandleFunc("POST /storage/zfs/replace", s.auth(s.replaceZFSDevice))
	mux.HandleFunc("POST /storage/zfs/cache", s.auth(s.addZFSCache))
	mux.HandleFunc("POST /storage/zfs/log", s.auth(s.addZFSLog))
	mux.HandleFunc("POST /storage/lvm/create", s.auth(s.createLVMPool))
	mux.HandleFunc("POST /storage/lvm/{vg}/remove", s.auth(s.removeVG))
	mux.HandleFunc("POST /storage/mdraid/create", s.auth(s.createMDArray))
	mux.HandleFunc("POST /storage/mdraid/{name}/destroy", s.auth(s.destroyMDArray))
	mux.HandleFunc("POST /storage/fs/create", s.auth(s.createFilesystemPool))

	// Shared storage: dedicated storage NIC + NFS/CIFS/Ceph mounts + iSCSI.
	mux.HandleFunc("GET /shared", s.auth(s.sharedPage))
	mux.HandleFunc("POST /shared/iface", s.auth(s.setStorageIface))
	mux.HandleFunc("POST /shared/nfs", s.auth(s.addNFS))
	mux.HandleFunc("POST /shared/cifs", s.auth(s.addCIFS))
	mux.HandleFunc("POST /shared/ceph", s.auth(s.addCeph))
	mux.HandleFunc("POST /shared/{id}/unmount", s.auth(s.unmountShared))
	mux.HandleFunc("POST /shared/iscsi/login", s.auth(s.iscsiLogin))
	mux.HandleFunc("POST /shared/iscsi/{id}/logout", s.auth(s.iscsiLogout))
	mux.HandleFunc("POST /shared/iscsi/adopt", s.auth(s.iscsiAdopt))
	mux.HandleFunc("POST /shared/overlay", s.auth(s.addOverlay))
	mux.HandleFunc("POST /shared/overlay/{id}/delete", s.auth(s.deleteOverlay))

	// Hyperconverged Ceph (RBD): stand up / grow the on-node cluster.
	mux.HandleFunc("GET /ceph", s.auth(s.cephPage))
	mux.HandleFunc("POST /ceph/bootstrap", s.auth(s.bootstrapCeph))
	mux.HandleFunc("POST /ceph/osd", s.auth(s.addCephOSD))
	mux.HandleFunc("POST /ceph/disk/clear", s.auth(s.clearDisk))
	mux.HandleFunc("POST /ceph/destroy", s.auth(s.destroyCeph))
	mux.HandleFunc("GET /api/iscsi/discover", s.auth(s.apiISCSIDiscover))
	mux.HandleFunc("GET /api/migrations", s.auth(s.apiMigrations))
	mux.HandleFunc("GET /api/drive-alerts", s.auth(s.apiDriveAlerts))
	mux.HandleFunc("GET /api/nic-alerts", s.auth(s.apiNICAlerts))
	mux.HandleFunc("POST /host/restart", s.auth(s.hostRestart))
	mux.HandleFunc("POST /host/shutdown", s.auth(s.hostShutdown))
	mux.HandleFunc("GET /api/instances/{id}/guest", s.auth(s.apiGuestInfo))

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
	mux.HandleFunc("POST /routing/eigrp", s.auth(s.rtSetEIGRP))
	mux.HandleFunc("POST /routing/eigrp/network", s.auth(s.rtAddEIGRPNetwork))
	mux.HandleFunc("POST /routing/eigrp/network/{i}/delete", s.auth(s.rtDelEIGRPNetwork))

	// M4: networking
	mux.HandleFunc("GET /networks", s.auth(s.networks))
	mux.HandleFunc("POST /networks", s.auth(s.createNetwork))
	mux.HandleFunc("POST /networks/{id}/delete", s.auth(s.deleteNetwork))
	// VMware-style data plane: bonds (LACP/etherchannel) + vSwitches (VLAN trunks).
	mux.HandleFunc("POST /networks/bonds", s.auth(s.createBond))
	mux.HandleFunc("POST /networks/bonds/{name}/delete", s.auth(s.deleteBond))
	mux.HandleFunc("POST /networks/vswitches", s.auth(s.createVSwitch))
	mux.HandleFunc("POST /networks/vswitches/{name}/delete", s.auth(s.deleteVSwitch))
	mux.HandleFunc("POST /networks/vswitches/{name}/bond", s.auth(s.bondVSwitch))
	// NSX-lite virtual routers (vRouter): a per-tenant FRR routing instance (LXC
	// container or network namespace) between a transit link and internal port groups.
	mux.HandleFunc("GET /vrouters", s.auth(s.vroutersPage))
	mux.HandleFunc("GET /vrouters/{id}/status", s.auth(s.apiVRouterStatus))
	mux.HandleFunc("GET /vrouters/{id}/diagram", s.auth(s.apiVRouterDiagram))
	mux.HandleFunc("POST /vrouters", s.auth(s.createVRouter))
	mux.HandleFunc("POST /vrouters/{id}/start", s.auth(s.startVRouter))
	mux.HandleFunc("POST /vrouters/{id}/stop", s.auth(s.stopVRouter))
	mux.HandleFunc("POST /vrouters/{id}/delete", s.auth(s.deleteVRouter))
	mux.HandleFunc("POST /vrouters/{id}/transit", s.auth(s.addTransitLink))
	mux.HandleFunc("POST /vrouters/{id}/internal", s.auth(s.attachInternal))
	mux.HandleFunc("POST /vrouters/{id}/internal/{idx}/dhcp", s.auth(s.updateInternalDHCP))
	mux.HandleFunc("POST /vrouters/{id}/internal/{idx}/update", s.auth(s.updateInternalNetwork))
	mux.HandleFunc("POST /vrouters/{id}/transit/update", s.auth(s.updateTransitLink))
	mux.HandleFunc("POST /vrouters/{id}/static/{i}/update", s.auth(s.vrUpdateStatic))
	mux.HandleFunc("POST /vrouters/{id}/ospf/net/{i}/update", s.auth(s.vrUpdateOSPFNet))
	mux.HandleFunc("POST /vrouters/{id}/bgp/neighbor/{i}/update", s.auth(s.vrUpdateBGPNeighbor))
	mux.HandleFunc("POST /vrouters/{id}/bgp/network/{i}/update", s.auth(s.vrUpdateBGPNet))
	mux.HandleFunc("POST /vrouters/{id}/static", s.auth(s.vrAddStatic))
	mux.HandleFunc("POST /vrouters/{id}/static/{i}/delete", s.auth(s.vrDelStatic))
	mux.HandleFunc("POST /vrouters/{id}/ospf", s.auth(s.vrSetOSPF))
	mux.HandleFunc("POST /vrouters/{id}/ospf/net", s.auth(s.vrAddOSPFNet))
	mux.HandleFunc("POST /vrouters/{id}/ospf/net/{i}/delete", s.auth(s.vrDelOSPFNet))
	mux.HandleFunc("POST /vrouters/{id}/bgp", s.auth(s.vrSetBGP))
	mux.HandleFunc("POST /vrouters/{id}/bgp/neighbor", s.auth(s.vrAddBGPNeighbor))
	mux.HandleFunc("POST /vrouters/{id}/bgp/neighbor/{i}/delete", s.auth(s.vrDelBGPNeighbor))
	mux.HandleFunc("POST /vrouters/{id}/bgp/network", s.auth(s.vrAddBGPNet))
	mux.HandleFunc("POST /vrouters/{id}/bgp/network/{i}/delete", s.auth(s.vrDelBGPNet))
	mux.HandleFunc("POST /vrouters/{id}/eigrp", s.auth(s.vrSetEIGRP))
	mux.HandleFunc("POST /vrouters/{id}/eigrp/net", s.auth(s.vrAddEIGRPNet))
	mux.HandleFunc("POST /vrouters/{id}/eigrp/net/{i}/delete", s.auth(s.vrDelEIGRPNet))
	// Zone-based firewall (ZBFW): a dedicated page that maps port groups to
	// security zones and applies allow/deny policies between them, enforced in the
	// vRouter runtime's own nftables instance.
	// Unified NSX-style firewall: one org-scoped document (VM Groups + Zones +
	// North-South/East-West rules), compiled onto the vRouter inet tables and the
	// host bridge table. Drag-and-drop membership posts with ?ajax=1.
	mux.HandleFunc("GET /vfirewall", s.auth(s.fwPage))
	mux.HandleFunc("POST /firewall", s.auth(s.fwSetEnabled))
	mux.HandleFunc("POST /firewall/group", s.auth(s.fwAddGroup))
	mux.HandleFunc("POST /firewall/group/{gid}/rename", s.auth(s.fwRenameGroup))
	mux.HandleFunc("POST /firewall/group/{gid}/delete", s.auth(s.fwDelGroup))
	mux.HandleFunc("POST /firewall/group/{gid}/members", s.auth(s.fwSetGroupMembers))
	mux.HandleFunc("POST /firewall/group/{gid}/zone", s.auth(s.fwSetGroupZone))
	mux.HandleFunc("POST /firewall/rule", s.auth(s.fwAddRule))
	mux.HandleFunc("POST /firewall/rule/{dir}/{i}/delete", s.auth(s.fwDelRule))
	mux.HandleFunc("POST /firewall/rule/{dir}/{i}/update", s.auth(s.fwUpdateRule))
	mux.HandleFunc("POST /firewall/rule/{dir}/{i}/move", s.auth(s.fwMoveRule))
	mux.HandleFunc("POST /sessions/{id}/forwards", s.auth(s.vmManage(s.addPortForward)))
	mux.HandleFunc("POST /sessions/{id}/forwards/{pfid}/delete", s.auth(s.vmManage(s.deletePortForward)))

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
	mux.HandleFunc("POST /cluster/nodes/join", s.auth(s.joinNode))
	mux.HandleFunc("GET /api/node-join", s.auth(s.apiNodeJoin))
	mux.HandleFunc("GET /migrate", s.auth(s.migrate))
	mux.HandleFunc("POST /import/vmware/connect", s.auth(s.vmwareConnect))
	mux.HandleFunc("POST /import/vmware/start", s.auth(s.vmwareImport))
	mux.HandleFunc("POST /migrate/plan/start", s.auth(s.migratePlanStart))
	mux.HandleFunc("GET /api/vmware-import", s.auth(s.apiVmwareImport))
	mux.HandleFunc("GET /api/vmware-import/{id}/log", s.auth(s.apiVmwareImportLog))
	mux.HandleFunc("POST /export/start", s.auth(s.exportStart))
	mux.HandleFunc("GET /api/vm-export", s.auth(s.apiExport))
	mux.HandleFunc("GET /api/vm-export/{id}/log", s.auth(s.apiExportLog))
	mux.HandleFunc("GET /export/{id}/download", s.auth(s.exportDownload))
	mux.HandleFunc("POST /export/{id}/delete", s.auth(s.exportDelete))
	mux.HandleFunc("POST /images/{name}/delete", s.auth(s.imageDelete))
	mux.HandleFunc("POST /cluster/nodes/{id}/probe", s.auth(s.probeNode))
	mux.HandleFunc("POST /cluster/nodes/{id}/delete", s.auth(s.deleteNode))
	mux.HandleFunc("POST /cluster/vms/{node}/{id}/{action}", s.auth(s.clusterVMAction))
	mux.HandleFunc("POST /cluster/import", s.auth(s.importImage))
	mux.HandleFunc("POST /sessions/{id}/migrate", s.auth(s.vmManage(s.migrateSession)))

	// Settings: Active Directory / LDAP authentication (admin).
	mux.HandleFunc("GET /settings/auth", s.auth(s.settingsAuth))
	mux.HandleFunc("POST /settings/auth", s.auth(s.saveAuthSettings))
	mux.HandleFunc("POST /settings/auth/test", s.auth(s.testAuthSettings))

	mux.HandleFunc("GET /members", s.auth(s.members))
	mux.HandleFunc("POST /members/add", s.auth(s.addMember))
	mux.HandleFunc("POST /members/{uid}/remove", s.auth(s.removeMember))
	mux.HandleFunc("POST /account/password", s.auth(s.changePassword))
	mux.HandleFunc("POST /members/{uid}/password", s.auth(s.resetPassword))

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
		// Cluster-admin reverse-proxy: another node forwarding an admin's action
		// from the VIP. Trusted via the shared-secret HMAC header.
		if p := s.clusterAdminPrincipal(r); p != nil {
			h(w, r, p)
			return
		}
		p := s.svc.Principal(r)
		if p == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		p.Unified = s.requestOnVIP(r)
		// For a browser form POST, surface an http.Error-style failure as a toast on
		// the page the user came from instead of a bare error page (see flashErrors).
		if convertibleForm(r) {
			fr := &flashRecorder{rw: w, convert: true}
			h(fr, r, p)
			if fr.capturing { // the handler wrote a text/plain 4xx/5xx — turn it into a flash
				msg := strings.TrimSpace(string(fr.buf))
				if msg == "" {
					msg = http.StatusText(fr.status)
				}
				setFlash(w, msg)
				dest := r.Referer()
				if dest == "" {
					dest = "/"
				}
				http.Redirect(w, r, dest, http.StatusSeeOther)
			}
			return
		}
		h(w, r, p)
	}
}

// convertibleForm reports whether a request is a normal browser form POST whose
// error response should become a flash toast. It excludes JSON/AJAX callers,
// the machine APIs (/api, /cluster/v1), and multipart uploads (which stream and
// run their own progress UI).
func convertibleForm(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/cluster/v1/") {
		return false
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") ||
		r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/") {
		return false
	}
	return true
}

// setFlash drops a short-lived, non-HttpOnly cookie carrying a one-off error
// message. foot.html reads it on the next page load, shows it as a toast, and
// clears it. Non-HttpOnly so the toast script can read it; the value is rendered
// with textContent (never as HTML), so it cannot inject markup.
func setFlash(w http.ResponseWriter, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "vdx_flash",
		Value:    url.QueryEscape(msg),
		Path:     "/",
		MaxAge:   30,
		SameSite: http.SameSiteLaxMode,
	})
}

// setFlashOK stashes a one-off SUCCESS message (shown as a green toast, not an
// error). The "ok:" prefix is recognized by the flash renderer in foot.html.
func setFlashOK(w http.ResponseWriter, msg string) { setFlash(w, "ok:"+msg) }

// flashRecorder defers an http.Error-style (text/plain 4xx/5xx) response on a
// convertible form POST so auth() can convert it into a flash + redirect. Any
// other response (success, redirect, JSON, HTML) passes straight through.
type flashRecorder struct {
	rw        http.ResponseWriter
	convert   bool
	capturing bool
	wrote     bool
	status    int
	buf       []byte
}

func (f *flashRecorder) Header() http.Header { return f.rw.Header() }

func (f *flashRecorder) WriteHeader(code int) {
	if f.wrote || f.capturing {
		return
	}
	// Only intercept plain-text errors — exactly what http.Error produces. Leaves
	// HTML pages and JSON bodies (even error ones) untouched.
	if f.convert && code >= 400 && strings.HasPrefix(f.rw.Header().Get("Content-Type"), "text/plain") {
		f.capturing = true
		f.status = code
		return
	}
	f.wrote = true
	f.rw.WriteHeader(code)
}

func (f *flashRecorder) Write(b []byte) (int, error) {
	if f.capturing {
		f.buf = append(f.buf, b...)
		return len(b), nil
	}
	if !f.wrote {
		f.wrote = true
		f.rw.WriteHeader(http.StatusOK)
	}
	return f.rw.Write(b)
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
	// Cluster-admin reverse-proxy requests are HMAC-authenticated and had CSRF
	// enforced at the originating (VIP) node, so skip the synchronizer check.
	if p != nil && p.TrustedPeer {
		return true
	}
	return r.FormValue("csrf") == csrfToken(p.Token())
}

func (s *Server) badCSRF(w http.ResponseWriter) { http.Error(w, "bad csrf token", http.StatusForbidden) }

// clusterAdminPrincipal returns a trusted admin principal when the request
// carries a valid cluster-admin reverse-proxy signature (another node forwarding
// an admin's action from the VIP), else nil.
func (s *Server) clusterAdminPrincipal(r *http.Request) *service.Principal {
	if s.clusterAuth == nil {
		return nil
	}
	sig := r.Header.Get("X-Cluster-Admin")
	user := r.Header.Get("X-Cluster-Admin-User")
	if sig == "" || user == "" {
		return nil
	}
	if !s.clusterAuth.Verify(sig, r.URL.Path, 30*time.Second) {
		return nil
	}
	return s.svc.TrustedAdminPrincipal(user)
}

// vmManage wraps a VM-scoped admin handler so that, on the VIP, a request for a
// VM owned by ANOTHER node is transparently reverse-proxied to that node — giving
// full per-VM management (details, resize, snapshots, migrate, delete) from the
// unified view, not just the aggregated list. Local VMs and non-admins fall
// through to the normal handler.
func (s *Server) vmManage(h func(http.ResponseWriter, *http.Request, *service.Principal)) func(http.ResponseWriter, *http.Request, *service.Principal) {
	return func(w http.ResponseWriter, r *http.Request, p *service.Principal) {
		if p.IsAdmin && !p.TrustedPeer && p.ActorKind == "user" {
			if mgmt, ok := s.svc.RemoteVMOwnerMgmt(r.PathValue("id")); ok {
				s.proxyToOwner(w, r, p, mgmt)
				return
			}
		}
		h(w, r, p)
	}
}

// proxyToOwner forwards the current admin request to the owning node's admin
// listener, authenticated with the cluster-admin HMAC header, and streams the
// response back. Redirects are passed through (not followed) so the browser stays
// on the VIP and re-proxies the next hop.
func (s *Server) proxyToOwner(w http.ResponseWriter, r *http.Request, p *service.Principal, mgmt string) {
	if s.clusterAuth == nil || p.User == nil {
		http.Error(w, "cluster management proxy unavailable", http.StatusBadGateway)
		return
	}
	host := mgmt
	if h, _, e := net.SplitHostPort(mgmt); e == nil {
		host = h
	}
	port := s.cfg.Cluster.AdminPort
	if port == 0 {
		port = 8766
	}
	target := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("X-Cluster-Admin", s.clusterAuth.Header(r.URL.Path))
	req.Header.Set("X-Cluster-Admin-User", p.User.Username)
	cl := &http.Client{
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := cl.Do(req)
	if err != nil {
		http.Error(w, "reach owning node: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// requestOnVIP reports whether this request arrived on the floating management
// VIP (as opposed to the node's own mgmt IP). The admin listener binds 0.0.0.0,
// so both addresses hit the same server; we distinguish them by the destination
// IP of the TCP connection. A VIP request drives the unified cluster-wide view;
// a node-IP request drives the standalone single-host view. "" VIP (follower or
// single host) → always standalone.
func (s *Server) requestOnVIP(r *http.Request) bool {
	vip := s.svc.ClusterVIP()
	if vip == "" {
		return false
	}
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || la == nil {
		return false
	}
	host, _, err := net.SplitHostPort(la.String())
	if err != nil {
		host = la.String()
	}
	return host == vip
}

// ---- rendering -----------------------------------------------------------

func (s *Server) render(w http.ResponseWriter, p *service.Principal, name, active string, data map[string]any) {
	view := map[string]any{
		"P":      p,
		"CSRF":   csrfToken(p.Token()),
		"Active": active,
	}
	// Cluster mode indicators for the chrome (topbar badge, nav). Unified = the
	// request came in on the VIP; NodeName/VIP label the current view.
	view["Version"] = service.BuildVersion()
	view["Unified"] = p.Unified
	view["Clustered"] = s.svc.ClusterEnabledRole()
	view["NodeName"] = s.svc.ClusterSelfName()
	if _, vip, _ := s.svc.ClusterLeader(); vip != "" {
		view["VIP"] = vip
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
