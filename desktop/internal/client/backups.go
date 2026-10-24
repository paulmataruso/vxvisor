package client

import "fmt"

// Backups, backup schedules, first-class backup targets, and iSCSI sessions.
// The list responses decode from PascalCase (the server entity/view structs
// carry no json tags); POST bodies are snake_case per the REST endpoints.

// Backup mirrors storage.Backup (the backups list row). Target is the display
// name filled in by the service layer.
type Backup struct {
	ID         int64  `json:"ID"`
	OrgID      int64  `json:"OrgID"`
	SessionID  string `json:"SessionID"`
	Name       string `json:"Name"`
	Path       string `json:"Path"`
	Compressor string `json:"Compressor"`
	SizeBytes  int64  `json:"SizeBytes"`
	Status     string `json:"Status"`
	Error      string `json:"Error"`
	TargetID   int64  `json:"TargetID"`
	Target     string `json:"Target"`
	CreatedAt  string `json:"CreatedAt"`
}

// BackupSchedule mirrors storage.Schedule (a recurring per-VM backup job).
type BackupSchedule struct {
	ID            int64  `json:"ID"`
	OrgID         int64  `json:"OrgID"`
	SessionID     string `json:"SessionID"`
	IntervalHours int    `json:"IntervalHours"`
	Keep          int    `json:"Keep"`
	Enabled       bool   `json:"Enabled"`
	LastRunAt     string `json:"LastRunAt"`
	NextRunAt     string `json:"NextRunAt"`
	TargetID      int64  `json:"TargetID"`
	Target        string `json:"Target"`
	CreatedAt     string `json:"CreatedAt"`
}

// BackupTarget mirrors service.BackupTargetView (a backup destination). Id 0 is
// the built-in local default.
type BackupTarget struct {
	ID      int64  `json:"ID"`
	Name    string `json:"Name"`
	Kind    string `json:"Kind"` // local | nfs | cifs | cephfs
	Path    string `json:"Path"`
	Mounted bool   `json:"Mounted"`
	Detail  string `json:"Detail"`
}

// ISCSISession mirrors service.ISCSISession (a kernel/DB iSCSI target row).
type ISCSISession struct {
	ID        int64  `json:"ID"`
	Portal    string `json:"Portal"`
	Target    string `json:"Target"`
	Status    string `json:"Status"`
	CreatedAt string `json:"CreatedAt"`
	Live      bool   `json:"Live"`
	Persisted bool   `json:"Persisted"`
}

// ---- backups -------------------------------------------------------------

// Backups lists the org's backups (newest first).
func (c *Client) Backups() ([]Backup, error) {
	var out []Backup
	if err := c.getJSON("/api/v1/backups", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateBackup runs an ad-hoc backup of a stopped instance. name defaults to
// "manual" server-side when empty; targetID 0 is the local default.
func (c *Client) CreateBackup(sessionID, name string, targetID int64) error {
	return c.apiPostJSON("/api/v1/backups/create", map[string]any{
		"session_id": sessionID, "name": name, "target_id": targetID,
	})
}

// RestoreBackup registers a backup as a new base image and returns the image name.
func (c *Client) RestoreBackup(id int64) (string, error) {
	var out struct {
		Image string `json:"image"`
	}
	err := c.apiPostDecode(fmt.Sprintf("/api/v1/backups/%d/restore", id), nil, &out)
	return out.Image, err
}

// DeleteBackup removes a backup by id.
func (c *Client) DeleteBackup(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/backups/%d/delete", id), nil)
}

// ---- backup schedules ----------------------------------------------------

// BackupSchedules lists the org's recurring backup schedules.
func (c *Client) BackupSchedules() ([]BackupSchedule, error) {
	var out []BackupSchedule
	if err := c.getJSON("/api/v1/backup-schedules", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSchedule creates a recurring backup for a VM every intervalHours,
// keeping the most recent keep backups, written to targetID (0 = local).
func (c *Client) CreateSchedule(sessionID string, intervalHours, keep int, targetID int64) error {
	return c.apiPostJSON("/api/v1/backup-schedules/create", map[string]any{
		"session_id": sessionID, "interval_hours": intervalHours,
		"keep": keep, "target_id": targetID,
	})
}

// DeleteSchedule removes a backup schedule by id.
func (c *Client) DeleteSchedule(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/backup-schedules/%d/delete", id), nil)
}

// ---- backup targets ------------------------------------------------------

// BackupTargets lists backup destinations (local default first, then configured).
func (c *Client) BackupTargets() ([]BackupTarget, error) {
	var out []BackupTarget
	if err := c.getJSON("/api/v1/backup-targets", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateBackupTarget creates a backup destination. For kind "local" only path is
// used; for nfs/cifs/cephfs server+share (and credentials) apply.
func (c *Client) CreateBackupTarget(name, kind, path, server, share, username, password, domain, vers, options string) error {
	return c.apiPostJSON("/api/v1/backup-targets", map[string]any{
		"name": name, "kind": kind, "path": path, "server": server, "share": share,
		"username": username, "password": password, "domain": domain,
		"vers": vers, "options": options,
	})
}

// DeleteBackupTarget removes a backup target by id (refused while still in use).
func (c *Client) DeleteBackupTarget(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/backup-targets/%d/delete", id), nil)
}

// TestBackupTarget mounts (if needed) and write-probes a target, returning the
// server's success message.
func (c *Client) TestBackupTarget(id int64) (string, error) {
	var out struct {
		Message string `json:"message"`
	}
	err := c.apiPostDecode(fmt.Sprintf("/api/v1/backup-targets/%d/test", id), nil, &out)
	return out.Message, err
}

// ---- iSCSI ---------------------------------------------------------------

// ISCSISessions lists iSCSI targets (union of live kernel + DB-recorded rows).
func (c *Client) ISCSISessions() ([]ISCSISession, error) {
	var out []ISCSISession
	if err := c.getJSON("/api/v1/iscsi", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ISCSILogin logs into a target over the storage NIC. CHAP args may be empty.
func (c *Client) ISCSILogin(portal, target, chapUser, chapPass, chapUserIn, chapPassIn string) error {
	return c.apiPostJSON("/api/v1/iscsi/login", map[string]any{
		"portal": portal, "target": target,
		"chap_user": chapUser, "chap_pass": chapPass,
		"chap_user_in": chapUserIn, "chap_pass_in": chapPassIn,
	})
}

// ISCSILogout logs out of (and removes) a recorded iSCSI target by id.
func (c *Client) ISCSILogout(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/iscsi/%d/logout", id), nil)
}
