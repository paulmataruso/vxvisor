package web

import (
	"io"
	"net/http"

	"vdxclone/internal/peer"
)

// Node-to-node cluster API (served on a SEPARATE listener bound to the cluster
// NIC, see cmd/vdxd). Every route is HMAC-authenticated with the shared cluster
// secret via peer.Auth.Middleware, so it is reachable only by cluster peers.

// SetClusterPeer installs the shared-secret authenticator for the peer API.
func (s *Server) SetClusterPeer(secret []byte) { s.clusterAuth = peer.NewAuth(secret) }

// PeerRoutes registers the authenticated peer API. No-op without a secret.
func (s *Server) PeerRoutes(mux *http.ServeMux) {
	if s.clusterAuth == nil {
		return
	}
	g := s.clusterAuth.Middleware
	mux.HandleFunc("GET /cluster/v1/accounts", g(s.peerAccounts))
	mux.HandleFunc("GET /cluster/v1/sessions", g(s.peerSessions))
	mux.HandleFunc("GET /cluster/v1/migrations", g(s.peerMigrations))
	mux.HandleFunc("POST /cluster/v1/sessions/{id}/{action}", g(s.peerAction))
	mux.HandleFunc("POST /cluster/v1/migrate-precheck", g(s.peerMigratePrecheck))
	mux.HandleFunc("POST /cluster/v1/migrate-recv", g(s.peerMigrateRecv))
	mux.HandleFunc("POST /cluster/v1/migrate-commit", g(s.peerMigrateCommit))
	mux.HandleFunc("POST /cluster/v1/migrate-abort", g(s.peerMigrateAbort))
	mux.HandleFunc("POST /cluster/v1/migrate-cold-commit", g(s.peerMigrateColdCommit))
	mux.HandleFunc("POST /cluster/v1/cold-disk-recv", g(s.peerColdDiskRecv))
	mux.HandleFunc("POST /cluster/v1/cold-cleanup", g(s.peerColdCleanup))
	mux.HandleFunc("POST /cluster/v1/migrate-recv-block", g(s.peerMigrateRecvBlock))
	mux.HandleFunc("POST /cluster/v1/migrate-nbd-stop", g(s.peerMigrateNBDStop))
	mux.HandleFunc("GET /cluster/v1/console/{id}/info", g(s.peerConsoleInfo))
	mux.HandleFunc("GET /cluster/v1/console/{id}/ws", g(s.peerConsoleWS))
	mux.HandleFunc("GET /cluster/v1/serial/{id}/ws", g(s.peerSerialWS))
	mux.HandleFunc("GET /cluster/v1/health", g(s.peerHealth))
}

// peerMigratePrecheck (destination) checks an inbound migration record (port
// group + address) before the source copies or streams anything.
func (s *Server) peerMigratePrecheck(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := s.svc.PrecheckMigration(body); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// peerMigrateRecv launches an inbound-migration QEMU on this (destination) node.
// The base64 qemu.Spec is the request body; the incoming port is a query param.
func (s *Server) peerMigrateRecv(w http.ResponseWriter, r *http.Request) {
	port := int(atoi(r.URL.Query().Get("port")))
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	actualPort, err := s.svc.LaunchMigrationReceiver(string(body), port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Report the port the receiver actually bound; the source streams to it (the
	// dst may pick a different free port than requested).
	writeJSON(w, map[string]int{"port": actualPort})
}

// peerMigrateCommit (destination) adopts a just-migrated VM into this node's DB.
func (s *Server) peerMigrateCommit(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := s.svc.AdoptMigratedSession(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// peerMigrateAbort (destination) tears down a receiver for a failed migration.
func (s *Server) peerMigrateAbort(w http.ResponseWriter, r *http.Request) {
	s.svc.AbortMigration(r.URL.Query().Get("id"))
	w.WriteHeader(http.StatusOK)
}

// peerMigrateColdCommit (destination) adopts a COLD-migrated (stopped) VM. It
// verifies the disk is present on this node before accepting, so a doomed handoff
// never strands the source.
func (s *Server) peerMigrateColdCommit(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := s.svc.AdoptColdMigratedSession(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// peerColdDiskRecv (destination) streams one incoming cold-migration file (disk /
// UEFI vars / cloud-init seed) to local storage and reports the path it landed at.
func (s *Server) peerColdDiskRecv(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	path, err := s.svc.ColdReceiveDisk(q.Get("id"), q.Get("kind"), q.Get("ext"), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"path": path})
}

// peerColdCleanup (destination) discards files staged for an aborted cold copy.
func (s *Server) peerColdCleanup(w http.ResponseWriter, r *http.Request) {
	s.svc.ColdCleanup(r.URL.Query().Get("id"))
	w.WriteHeader(http.StatusOK)
}

// peerMigrateRecvBlock (destination) launches a block-live (NBD) receiver: creates
// the target disk at the source's virtual size, launches the incoming QEMU bound
// to the cluster IP, and exports the disk over NBD. Returns the endpoint the
// source mirrors + migrates to.
func (s *Server) peerMigrateRecvBlock(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port := int(atoi(q.Get("port")))
	vsize := atoi(q.Get("vsize"))
	bindIP := q.Get("bind")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	info, err := s.svc.LaunchBlockMigrationReceiver(string(body), port, bindIP, vsize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, info)
}

// peerMigrateNBDStop (destination) removes the NBD export at pre-switchover, before
// the guest resumes.
func (s *Server) peerMigrateNBDStop(w http.ResponseWriter, r *http.Request) {
	s.svc.StopBlockExport(r.URL.Query().Get("id"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) selfNode() string {
	if r := s.svc.Role(); r != nil {
		return r.SelfName()
	}
	return "local"
}

// peerAccounts serves the leader's account snapshot for a follower to apply.
func (s *Server) peerAccounts(w http.ResponseWriter, r *http.Request) {
	snap, err := s.svc.AccountSnapshotJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(snap)
}

// peerSessions serves this node's VM list (all orgs) for the aggregator.
func (s *Server) peerSessions(w http.ResponseWriter, r *http.Request) {
	vms, err := s.svc.AllLocalSessions(s.selfNode())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, vms)
}

// peerMigrations serves this node's in-flight/recent migration tracker for the
// VIP aggregator. Each migration lives only in its driving node's tracker.
func (s *Server) peerMigrations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.svc.MigrationsSnapshot())
}

// peerAction performs a lifecycle action on a VM hosted on this node.
func (s *Server) peerAction(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.LocalVMAction(r.PathValue("id"), r.PathValue("action")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// peerHealth reports this node's live capacity.
func (s *Server) peerHealth(w http.ResponseWriter, r *http.Request) {
	h := map[string]any{"node": s.selfNode()}
	if mc := s.svc.Metrics(); mc != nil {
		live := mc.Live().Host
		h["cpu_pct"] = live.CPUPct
		h["mem_total"] = live.MemTotal
		h["mem_used"] = live.MemUsed
	}
	writeJSON(w, h)
}
