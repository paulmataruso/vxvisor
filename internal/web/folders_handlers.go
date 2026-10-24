package web

import (
	"net/http"
	"strconv"

	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// folderNode is one node of the inventory tree as rendered on the instances
// page: a folder with its child folders and the VMs filed directly in it.
type folderNode struct {
	ID       int64
	Name     string
	Children []*folderNode
	VMs      []*session.Session
}

// buildFolderTree arranges the flat folder list + VM→folder map into a nested
// tree, returning the top-level folders and the VMs that live at the root
// (unassigned). Order follows the inputs (folders already come back name-sorted).
func buildFolderTree(sessions []*session.Session, folders []service.Folder, members map[string]int64) (roots []*folderNode, rootVMs []*session.Session) {
	byID := make(map[int64]*folderNode, len(folders))
	for _, f := range folders {
		byID[f.ID] = &folderNode{ID: f.ID, Name: f.Name}
	}
	for _, f := range folders {
		n := byID[f.ID]
		if parent := byID[f.ParentID]; f.ParentID != 0 && parent != nil {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	for _, s := range sessions {
		if fid, ok := members[s.ID]; ok {
			if n := byID[fid]; n != nil {
				n.VMs = append(n.VMs, s)
				continue
			}
		}
		rootVMs = append(rootVMs, s)
	}
	return roots, rootVMs
}

// Inventory-folder mutations for the instances page. Like the firewall page,
// each runs through folderDo, which answers a drag-and-drop fetch (?ajax=1 →
// JSON) or redirects back to /instances for a plain form POST. Authorization and
// audit live in the service; these just parse the request.

func (s *Server) folderDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func() error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	err := fn()
	if r.URL.Query().Get("ajax") != "" || r.FormValue("ajax") != "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/instances", http.StatusSeeOther)
}

func (s *Server) folderCreate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.folderDo(w, r, p, func() error {
		parent, _ := strconv.ParseInt(r.FormValue("parent"), 10, 64)
		_, err := s.svc.CreateFolder(p, parent, r.FormValue("name"), clientIP(r))
		return err
	})
}

func (s *Server) folderRename(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.folderDo(w, r, p, func() error {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		return s.svc.RenameFolder(p, id, r.FormValue("name"), clientIP(r))
	})
}

func (s *Server) folderDelete(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.folderDo(w, r, p, func() error {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		return s.svc.DeleteFolder(p, id, clientIP(r))
	})
}

func (s *Server) folderMove(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.folderDo(w, r, p, func() error {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		parent, _ := strconv.ParseInt(r.FormValue("parent"), 10, 64)
		return s.svc.MoveFolder(p, id, parent, clientIP(r))
	})
}

func (s *Server) folderMoveVM(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.folderDo(w, r, p, func() error {
		folder, _ := strconv.ParseInt(r.FormValue("folder"), 10, 64)
		return s.svc.MoveVM(p, r.FormValue("vm"), folder, clientIP(r))
	})
}
