package service

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// Inventory folders: a VMware-style nestable tree for organizing an org's
// instances. Folders are org-scoped and shared; a VM lives in at most one folder
// (no row in vm_folder_members = root/ungrouped). The source of truth is the two
// tables from migration 43; this service is the authz + audit layer over them.

// Folder is one node of the inventory tree. ParentID 0 means a top-level folder.
type Folder struct {
	ID       int64  `json:"ID"`
	ParentID int64  `json:"ParentID"`
	Name     string `json:"Name"`
}

// FolderData is the whole org inventory tree plus the VM→folder assignments, in
// one payload the web dashboard and the desktop client both join against their
// existing session list. Members maps a VM id to its folder id (VMs absent from
// the map are at the root).
type FolderData struct {
	Folders []Folder         `json:"Folders"`
	Members map[string]int64 `json:"Members"`
}

// ListFolderData returns every folder and VM→folder assignment for the caller's
// org. Read access is any org member/viewer (same as listing VMs).
func (s *Service) ListFolderData(p *Principal) (FolderData, error) {
	out := FolderData{Members: map[string]int64{}}
	if p.OrgID == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(parent_id,0), name FROM vm_folders WHERE org_id=? ORDER BY name`, p.OrgID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.ParentID, &f.Name); err != nil {
			rows.Close()
			return out, err
		}
		out.Folders = append(out.Folders, f)
	}
	rows.Close()

	mrows, err := s.db.Query(`SELECT vm_id, folder_id FROM vm_folder_members WHERE org_id=?`, p.OrgID)
	if err != nil {
		return out, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var vm string
		var fid int64
		if err := mrows.Scan(&vm, &fid); err != nil {
			return out, err
		}
		out.Members[vm] = fid
	}
	return out, nil
}

// CreateFolder adds a folder under parentID (0 = top level) and returns its id.
func (s *Service) CreateFolder(p *Principal, parentID int64, name, ip string) (int64, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("folder name required")
	}
	if len(name) > 120 {
		name = name[:120]
	}
	if parentID != 0 {
		if err := s.folderInOrg(p.OrgID, parentID); err != nil {
			return 0, err
		}
	}
	res, err := s.db.Exec(`INSERT INTO vm_folders (org_id, parent_id, name) VALUES (?, ?, ?)`,
		p.OrgID, nullIfZero(parentID), name)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	s.audit(p, p.OrgID, "folder.create", "folder", strconv.FormatInt(id, 10), ip, map[string]any{"name": name, "parent": parentID})
	return id, nil
}

// RenameFolder renames a folder in the caller's org.
func (s *Service) RenameFolder(p *Principal, id int64, name, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("folder name required")
	}
	if len(name) > 120 {
		name = name[:120]
	}
	if err := s.folderInOrg(p.OrgID, id); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE vm_folders SET name=? WHERE id=? AND org_id=?`, name, id, p.OrgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "folder.rename", "folder", strconv.FormatInt(id, 10), ip, map[string]any{"name": name})
	return nil
}

// DeleteFolder removes a folder without deleting any VMs: its child folders and
// its VMs are reparented to the folder's own parent (the root if it was
// top-level), so nothing is orphaned and no instance is touched.
func (s *Service) DeleteFolder(p *Principal, id int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if err := s.folderInOrg(p.OrgID, id); err != nil {
		return err
	}
	var parent sql.NullInt64
	if err := s.db.QueryRow(`SELECT parent_id FROM vm_folders WHERE id=? AND org_id=?`, id, p.OrgID).Scan(&parent); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Reparent child folders to this folder's parent.
	if parent.Valid {
		if _, err := tx.Exec(`UPDATE vm_folders SET parent_id=? WHERE parent_id=? AND org_id=?`, parent.Int64, id, p.OrgID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE vm_folder_members SET folder_id=? WHERE folder_id=? AND org_id=?`, parent.Int64, id, p.OrgID); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`UPDATE vm_folders SET parent_id=NULL WHERE parent_id=? AND org_id=?`, id, p.OrgID); err != nil {
			return err
		}
		// Moving members to the root = dropping their membership rows.
		if _, err := tx.Exec(`DELETE FROM vm_folder_members WHERE folder_id=? AND org_id=?`, id, p.OrgID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM vm_folders WHERE id=? AND org_id=?`, id, p.OrgID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "folder.delete", "folder", strconv.FormatInt(id, 10), ip, nil)
	return nil
}

// MoveFolder reparents a folder under newParentID (0 = top level), refusing a
// move that would create a cycle (into itself or one of its own descendants).
func (s *Service) MoveFolder(p *Principal, id, newParentID int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if err := s.folderInOrg(p.OrgID, id); err != nil {
		return err
	}
	if id == newParentID {
		return fmt.Errorf("cannot move a folder into itself")
	}
	if newParentID != 0 {
		if err := s.folderInOrg(p.OrgID, newParentID); err != nil {
			return err
		}
		// Walk newParent's ancestry; if we hit id, this move makes a cycle.
		cur := newParentID
		for cur != 0 {
			if cur == id {
				return fmt.Errorf("cannot move a folder into its own subtree")
			}
			var par sql.NullInt64
			if err := s.db.QueryRow(`SELECT parent_id FROM vm_folders WHERE id=? AND org_id=?`, cur, p.OrgID).Scan(&par); err != nil {
				return err
			}
			if !par.Valid {
				break
			}
			cur = par.Int64
		}
	}
	if _, err := s.db.Exec(`UPDATE vm_folders SET parent_id=? WHERE id=? AND org_id=?`, nullIfZero(newParentID), id, p.OrgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "folder.move", "folder", strconv.FormatInt(id, 10), ip, map[string]any{"parent": newParentID})
	return nil
}

// MoveVM files a VM into folderID, or to the root when folderID is 0 (which
// removes its membership row). Both the VM and the folder must be in the org.
func (s *Service) MoveVM(p *Principal, vmID string, folderID int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if err := s.vmInOrg(p.OrgID, vmID); err != nil {
		return err
	}
	if folderID == 0 {
		if _, err := s.db.Exec(`DELETE FROM vm_folder_members WHERE vm_id=? AND org_id=?`, vmID, p.OrgID); err != nil {
			return err
		}
		s.audit(p, p.OrgID, "folder.move_vm", "session", vmID, ip, map[string]any{"folder": 0})
		return nil
	}
	if err := s.folderInOrg(p.OrgID, folderID); err != nil {
		return err
	}
	// Upsert the single-folder membership.
	if _, err := s.db.Exec(`INSERT INTO vm_folder_members (vm_id, org_id, folder_id) VALUES (?, ?, ?)
		ON CONFLICT(vm_id) DO UPDATE SET folder_id=excluded.folder_id, org_id=excluded.org_id`,
		vmID, p.OrgID, folderID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "folder.move_vm", "session", vmID, ip, map[string]any{"folder": folderID})
	return nil
}

// folderInOrg returns nil only if the folder exists in the given org.
func (s *Service) folderInOrg(orgID, id int64) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM vm_folders WHERE id=? AND org_id=?`, id, orgID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// vmInOrg returns nil only if the VM exists in the given org.
func (s *Service) vmInOrg(orgID int64, vmID string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE id=? AND org_id=?`, vmID, orgID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
