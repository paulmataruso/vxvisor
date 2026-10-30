package web

import (
	"encoding/json"
	"io"
	"net/http"

	"vdxclone/internal/fabric"
)

// The VXVisor Fabric's node-to-node API (signed peer API, cluster NIC only):
// intent sync + the unanimous two-phase commit, preflight, DF ping, status.
// Refusals carry the member's own message as {"error": ...} with 409.

func peerFail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) peerFabricIntent(w http.ResponseWriter, r *http.Request) {
	in, err := s.svc.FabricPeerIntent()
	if err != nil {
		peerFail(w, err)
		return
	}
	writeJSON(w, in)
}

func (s *Server) peerFabricPrepare(w http.ResponseWriter, r *http.Request) {
	var p fabric.Proposal
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&p); err != nil {
		peerFail(w, err)
		return
	}
	if err := s.svc.FabricPeerPrepare(p); err != nil {
		peerFail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) peerFabricCommit(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.FabricPeerCommit(r.URL.Query().Get("id")); err != nil {
		peerFail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) peerFabricAbort(w http.ResponseWriter, r *http.Request) {
	s.svc.FabricPeerAbort(r.URL.Query().Get("id"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) peerFabricPreflight(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fabric fabric.Spec `json:"fabric"`
		Host   fabric.Host `json:"host"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		peerFail(w, err)
		return
	}
	writeJSON(w, s.svc.FabricLocalPreflight(req.Fabric, req.Host))
}

func (s *Server) peerFabricDFPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fabric string   `json:"fabric"`
		TEPs   []string `json:"teps"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		peerFail(w, err)
		return
	}
	writeJSON(w, s.svc.FabricLocalDFPing(req.Fabric, req.TEPs))
}

func (s *Server) peerFabricStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.svc.FabricLocalStatus())
}

func (s *Server) peerFabricNICs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.svc.FabricLocalNICs())
}
