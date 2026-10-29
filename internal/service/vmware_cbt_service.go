package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/vmware"
)

// CBT warm import from vCenter/ESXi (docs/CBT-IMPORT.md).
//
// Opt-in per VM: the operator ticks "Use CBT (warm migration)", and that consent
// (stored as consent=1 on the import row) is the only thing that lets vdxd
// change the source — and then only through internal/vmware/cbt.go: enable CBT,
// create/remove our own vxvisor-cbt-* snapshots, and (if asked at cut-over) a
// VMware Tools guest shutdown. The source keeps running while the base copy and
// periodic delta passes sync a sparse raw staging file per disk; the user then
// cuts over (source off → final delta → convert + create the instance through
// the same tail as every other import). CBT is put back the way we found it.
//
// Every bit of state is in the DB (migration 53) and every job is driven from
// it by CBTTick (the worker calls it every few seconds, and once at boot), so a
// vdxd restart resumes syncing, abandons an interrupted cut-over back to
// syncing, and removes every snapshot we recorded — and only those.
//
// The unchecked import path (runVMwareImport) is untouched and stays strictly
// read-only on the source.

const (
	cbtStarting  = "starting"  // base copy queued (or being retried)
	cbtBaseCopy  = "base-copy" // reading the full base from the first snapshot
	cbtSyncing   = "syncing"   // base done; delta passes on an interval / on demand
	cbtCutover   = "cutover"   // waiting for the source to power off, then the final pass
	cbtFinishing = "finishing" // converting staging → target + creating the instance
	cbtCleanup   = "cleanup"   // removing our snapshots, restoring CBT, deleting staging
	cbtDone      = "done"
	cbtCancelled = "cancelled"
	cbtError     = "error"
)

func cbtTerminal(st string) bool { return st == cbtDone || st == cbtCancelled || st == cbtError }

// Tunables.
const (
	cbtDefaultInterval = 30 * time.Minute
	cbtMinInterval     = 5 * time.Minute
	cbtMaxInterval     = 24 * time.Hour
	cbtMaxFailures     = 5               // consecutive failed passes before the import gives up
	cbtRetryDelay      = 2 * time.Minute // after a failed pass / base copy
	cbtCleanupRetry    = time.Minute     // while vCenter can't be reached for cleanup
	cbtPowerOffWait    = time.Hour       // cut-over waits this long for the source to power off
	// cbtOrphanGrace: a snapshot record with no moref (vdxd died during the
	// create call) younger than this may still be being created on vCenter, so
	// "not found by name" is not yet proof it never existed.
	cbtOrphanGrace = 15 * time.Minute
	cbtKeepAlive   = 5 * time.Minute
	cbtStagePrefix = ".vdxcbt-"
)

// cbtSource is the vSphere side of a warm import: *vmware.Client in production
// (via cbtVC), a fake in tests (vcsim has no QueryChangedDiskAreas).
type cbtSource interface {
	CBTState(ctx context.Context, moid string) (vmware.CBTVMState, error)
	SetChangeTracking(ctx context.Context, consent vmware.CBTConsent, enabled bool) error
	CreateCBTSnapshot(ctx context.Context, consent vmware.CBTConsent, name, description string) (string, error)
	RemoveCBTSnapshot(ctx context.Context, consent vmware.CBTConsent, moref, name string) (bool, error)
	ShutdownGuestOS(ctx context.Context, consent vmware.CBTConsent) error
	SnapshotDisks(ctx context.Context, moid, snapMoref string) ([]vmware.CBTDisk, error)
	QueryChangedAreas(ctx context.Context, moid, snapMoref string, deviceKey int32, capacity int64, changeID string) ([]vmware.ChangedArea, error)
	GetVM(ctx context.Context, moid string) (vmware.VMInfo, error)
	Close(ctx context.Context)
}

// cbtVC is the production cbtSource: a vSphere session kept alive for the
// length of a job (a base copy makes no API calls for hours).
type cbtVC struct {
	*vmware.Client
	stop func()
}

func (v *cbtVC) Close(ctx context.Context) { v.stop(); v.Client.Close(ctx) }

func dialCBTSource(ctx context.Context, c vmware.Creds) (cbtSource, error) {
	cli, err := vmware.Connect(ctx, c)
	if err != nil {
		return nil, err
	}
	return &cbtVC{Client: cli, stop: cli.KeepAlive(cbtKeepAlive)}, nil
}

// cbtRuntime is the in-memory side: which import a job currently owns, and the
// seams tests replace.
type cbtRuntime struct {
	mu   sync.Mutex
	jobs map[string]*cbtJob
	wg   sync.WaitGroup

	dial      func(ctx context.Context, c vmware.Creds) (cbtSource, error)
	open      func(ctx context.Context, src cbtSource, r *cbtImport, pass string, disk vmware.CBTDisk, snap string) (*cbtDisk, error)
	finish    func(id string, lg *importLogger, vm vmware.VMInfo, disks []string, r *cbtImport, p *Principal, ip string) (image, sessionID string, err error)
	ready     func(p *Principal) bool
	now       func() time.Time
	pollEvery time.Duration // power-state polling during cut-over
}

type cbtJob struct {
	kind    string // base | delta | cutover | cleanup
	cancel  context.CancelFunc
	started time.Time
	done    atomic.Int64 // bytes copied this job
	total   atomic.Int64 // bytes to copy this job (known once the areas are queried)
}

var cbtInitMu sync.Mutex

// cbtRT returns the runtime, creating it with the production seams on first use.
func (s *Service) cbtRT() *cbtRuntime {
	cbtInitMu.Lock()
	defer cbtInitMu.Unlock()
	if s.cbt == nil {
		s.cbt = &cbtRuntime{}
	}
	rt := s.cbt
	if rt.jobs == nil {
		rt.jobs = map[string]*cbtJob{}
	}
	if rt.dial == nil {
		rt.dial = dialCBTSource
	}
	if rt.open == nil {
		rt.open = s.cbtOpenVDDK
	}
	if rt.finish == nil {
		rt.finish = s.cbtFinish
	}
	if rt.ready == nil {
		rt.ready = s.VDDKReady
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.pollEvery == 0 {
		rt.pollEvery = 10 * time.Second
	}
	return rt
}

// claim makes a job the owner of an import; false if one already is.
func (rt *cbtRuntime) claim(id, kind string) (*cbtJob, context.Context, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, busy := rt.jobs[id]; busy {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &cbtJob{kind: kind, cancel: cancel, started: rt.now()}
	rt.jobs[id] = j
	return j, ctx, true
}

func (rt *cbtRuntime) release(id string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if j := rt.jobs[id]; j != nil {
		j.cancel()
		delete(rt.jobs, id)
	}
}

func (rt *cbtRuntime) job(id string) *cbtJob {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.jobs[id]
}

// cbtRun runs fn as the owning job of import id (claimed by the caller). After
// fn, still owning the import, it honors a cancel request and finishes any
// cleanup fn moved the import into — so a cancel or a fatal error is fully
// cleaned up before another job can touch the import.
func (s *Service) cbtRun(id string, j *cbtJob, ctx context.Context, fn func(ctx context.Context, j *cbtJob)) {
	rt := s.cbtRT()
	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		defer rt.release(id)
		func() {
			defer func() {
				if v := recover(); v != nil {
					log.Printf("vmware-cbt %s: %s job panicked: %v", id, j.kind, v)
					s.cbtExec(`UPDATE vmware_cbt_imports SET last_error=? WHERE id=?`, fmt.Sprintf("internal error in %s: %v", j.kind, v), id)
				}
			}()
			fn(ctx, j)
		}()
		r, err := s.cbtLoad(id)
		if err != nil || cbtTerminal(r.State) {
			return
		}
		if r.CancelReq && r.State != cbtCleanup && r.State != cbtFinishing {
			s.cbtBeginCleanup(id, cbtCancelled, "cancel requested")
			r.State, r.NextRun = cbtCleanup, 0
		}
		if r.State == cbtCleanup && r.NextRun <= rt.now().Unix() {
			s.cbtCleanupJob(context.Background(), id)
		}
	}()
}

// cbtStart claims import id for a job and runs it; false if a job owns it.
func (s *Service) cbtStart(id, kind string, fn func(ctx context.Context, j *cbtJob)) bool {
	j, ctx, ok := s.cbtRT().claim(id, kind)
	if !ok {
		return false
	}
	s.cbtRun(id, j, ctx, fn)
	return true
}

// cbtWait blocks until no job is running (tests).
func (s *Service) cbtWait() { s.cbtRT().wg.Wait() }

// ---- DB row ----------------------------------------------------------------

type cbtImport struct {
	ID, URL, Host, User, PassEnc string
	Insecure                     bool
	MOID, VMName                 string
	Consent                      bool
	CBTOrig                      int // -1 not read yet, 0 off, 1 on
	CBTByUs                      bool
	State, EndState              string
	CancelReq                    bool
	Step, LastErr                string
	Fails                        int
	OSType                       string
	PoolID                       int64
	Interval                     int64 // seconds
	NextRun, LastSync            int64 // unix seconds
	Passes                       int
	BaseBytes                    int64
	ShutdownGuest                bool
	ResultImage, ResultSession   string
	OrgID, UserID                int64
	CreatedAt, FinishedAt        string
}

const cbtCols = `id,vc_url,vc_host,vc_user,vc_pass_enc,vc_insecure,moid,vm_name,consent,cbt_orig,cbt_enabled_by_us,
	state,end_state,cancel_req,step,last_error,fail_count,os_type,target_pool_id,interval_sec,next_run_at,last_sync_at,
	passes,base_bytes,shutdown_guest,result_image,result_session,org_id,user_id,created_at,finished_at`

func scanCBT(sc interface{ Scan(...any) error }) (*cbtImport, error) {
	r := &cbtImport{}
	err := sc.Scan(&r.ID, &r.URL, &r.Host, &r.User, &r.PassEnc, &r.Insecure, &r.MOID, &r.VMName, &r.Consent, &r.CBTOrig, &r.CBTByUs,
		&r.State, &r.EndState, &r.CancelReq, &r.Step, &r.LastErr, &r.Fails, &r.OSType, &r.PoolID, &r.Interval, &r.NextRun, &r.LastSync,
		&r.Passes, &r.BaseBytes, &r.ShutdownGuest, &r.ResultImage, &r.ResultSession, &r.OrgID, &r.UserID, &r.CreatedAt, &r.FinishedAt)
	return r, err
}

func (s *Service) cbtLoad(id string) (*cbtImport, error) {
	return scanCBT(s.db.QueryRow(`SELECT `+cbtCols+` FROM vmware_cbt_imports WHERE id=?`, id))
}

// cbtList returns imports matching where (fully read before returning — the DB
// is a single connection, so no other statement may run while rows are open).
func (s *Service) cbtList(where string, args ...any) ([]*cbtImport, error) {
	rows, err := s.db.Query(`SELECT `+cbtCols+` FROM vmware_cbt_imports WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*cbtImport
	for rows.Next() {
		r, err := scanCBT(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) cbtExec(q string, args ...any) int64 {
	res, err := s.db.Exec(q, args...)
	if err != nil {
		log.Printf("vmware-cbt: %v (%s)", err, strings.Fields(q)[0])
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

func (s *Service) cbtStep(id, step string) {
	s.cbtExec(`UPDATE vmware_cbt_imports SET step=?, updated_at=datetime('now') WHERE id=?`, step, id)
}

type cbtDiskRow struct {
	Key      int32
	Idx      int
	Label    string
	Capacity int64
	Staging  string
	ChangeID string
}

func (s *Service) cbtDisks(id string) ([]cbtDiskRow, error) {
	rows, err := s.db.Query(`SELECT device_key,idx,label,capacity,staging,change_id FROM vmware_cbt_disks WHERE import_id=? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cbtDiskRow
	for rows.Next() {
		var d cbtDiskRow
		if err := rows.Scan(&d.Key, &d.Idx, &d.Label, &d.Capacity, &d.Staging, &d.ChangeID); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type cbtSnapRec struct {
	ID        int64
	Name      string
	Moref     string
	CreatedAt int64
}

func (s *Service) cbtPendingSnaps(id string) ([]cbtSnapRec, error) {
	rows, err := s.db.Query(`SELECT id,name,moref,created_at FROM vmware_cbt_snapshots WHERE import_id=? AND removed_at=0 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cbtSnapRec
	for rows.Next() {
		var r cbtSnapRec
		if err := rows.Scan(&r.ID, &r.Name, &r.Moref, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// cbtLogger appends to the import's durable log (a warm import spans many jobs
// and restarts, so unlike a cold import the log is never truncated).
func (s *Service) cbtLogger(id string) *importLogger {
	lg := &importLogger{id: id}
	dir := s.importLogDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return lg
	}
	if f, err := os.OpenFile(filepath.Join(dir, "vmware-"+id+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		lg.f = f
	}
	return lg
}

// ---- user actions ------------------------------------------------------------

func clampCBTInterval(min int) time.Duration {
	d := time.Duration(min) * time.Minute
	switch {
	case min <= 0:
		return cbtDefaultInterval
	case d < cbtMinInterval:
		return cbtMinInterval
	case d > cbtMaxInterval:
		return cbtMaxInterval
	}
	return d
}

// VMwareImportCBT starts a CBT warm import of one VM (admin only). Calling it IS
// the operator's consent — given by ticking "Use CBT (warm migration)" — to
// enable CBT on that VM and take short-lived snapshots of it. The vCenter
// password is stored sealed (encSeal) so the import can resume and clean up
// after a restart, and is wiped when the import ends.
func (s *Service) VMwareImportCBT(p *Principal, c vmware.Creds, moid, osType string, targetPoolID int64, intervalMin int, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	rt := s.cbtRT()
	moid = strings.TrimSpace(moid)
	if moid == "" {
		return "", fmt.Errorf("select a VM to import")
	}
	if !rt.ready(p) {
		return "", fmt.Errorf("warm migration (CBT) reads the source through VDDK — install VDDK on this page first")
	}
	if c.Pass == "" {
		// The sealed password is how a resumed or cleanup job reconnects.
		return "", fmt.Errorf("a vCenter password is required for a warm migration")
	}
	if _, _, err := s.ResolveDiskTarget(p, targetPoolID); err != nil {
		return "", err
	}
	if osType != "windows" {
		osType = "linux"
	}
	sealed, err := s.encSeal(c.Pass)
	if err != nil {
		return "", fmt.Errorf("seal vCenter password: %w", err)
	}
	interval := clampCBTInterval(intervalMin)
	id := uuid.NewString()
	var uid int64
	if p.User != nil {
		uid = p.User.ID
	}
	_, err = s.db.Exec(`INSERT INTO vmware_cbt_imports(id,org_id,user_id,vc_url,vc_host,vc_user,vc_pass_enc,vc_insecure,moid,consent,
		state,step,os_type,target_pool_id,interval_sec) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)`,
		id, p.OrgID, uid, c.URL, vcHost(c.URL), c.User, sealed, c.Insecure, moid, cbtStarting, "queued", osType, targetPoolID, int64(interval/time.Second))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", fmt.Errorf("a warm migration of this VM is already in progress")
		}
		return "", err
	}
	s.audit(p, p.OrgID, "vmware.cbt_start", "vmware", moid, ip, map[string]any{
		"import": id, "host": vcHost(c.URL), "user": c.User, "pool_id": targetPoolID, "interval_min": int(interval / time.Minute),
		"consent": "enable CBT + temporary vxvisor-cbt-* snapshots on this VM",
	})
	s.cbtStart(id, "base", func(ctx context.Context, j *cbtJob) { s.cbtBaseJob(ctx, j, id) })
	return id, nil
}

// CBTSyncNow runs a delta pass now instead of waiting for the interval.
func (s *Service) CBTSyncNow(p *Principal, id, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	r, err := s.cbtLoad(id)
	if err != nil {
		return fmt.Errorf("no such warm import")
	}
	if r.State != cbtSyncing || r.CancelReq {
		return fmt.Errorf("can only sync a warm import that is syncing (this one is %s)", r.State)
	}
	if !s.cbtStart(id, "delta", func(ctx context.Context, j *cbtJob) { s.cbtDeltaJob(ctx, j, id) }) {
		return fmt.Errorf("a pass is already running for this import")
	}
	s.audit(p, p.OrgID, "vmware.cbt_sync_now", "vmware", r.MOID, ip, map[string]any{"import": id})
	return nil
}

// CBTCutover starts the cut-over: one more pass while the source runs, then
// (optionally, via VMware Tools) a guest shutdown — otherwise the operator powers
// the source off — then the final pass, the conversion, and the instance.
func (s *Service) CBTCutover(p *Principal, id string, shutdownGuest bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	rt := s.cbtRT()
	r, err := s.cbtLoad(id)
	if err != nil {
		return fmt.Errorf("no such warm import")
	}
	j, ctx, ok := rt.claim(id, "cutover")
	if !ok {
		return fmt.Errorf("a sync pass is running for this import — try again when it finishes")
	}
	n := s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, shutdown_guest=?, last_error='', step=?, updated_at=datetime('now')
		WHERE id=? AND state=? AND cancel_req=0`, cbtCutover, shutdownGuest, "cut-over starting", id, cbtSyncing)
	if n == 0 {
		rt.release(id)
		return fmt.Errorf("can only cut over a warm import whose base copy is done and that is syncing (this one is %s)", r.State)
	}
	s.audit(p, p.OrgID, "vmware.cbt_cutover", "vmware", r.MOID, ip, map[string]any{"import": id, "shutdown_guest": shutdownGuest})
	s.cbtRun(id, j, ctx, func(ctx context.Context, j *cbtJob) { s.cbtCutoverJob(ctx, j, id, p, ip) })
	return nil
}

// CBTCancel stops a warm import: removes our snapshots, restores CBT, deletes
// the staging files. Refused once the cut-over is converting (finishing).
func (s *Service) CBTCancel(p *Principal, id, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	r, err := s.cbtLoad(id)
	if err != nil {
		return fmt.Errorf("no such warm import")
	}
	n := s.cbtExec(`UPDATE vmware_cbt_imports SET cancel_req=1, updated_at=datetime('now')
		WHERE id=? AND state NOT IN ('finishing','cleanup','done','cancelled','error')`, id)
	if n == 0 {
		return fmt.Errorf("this import can't be cancelled now (it is %s)", r.State)
	}
	s.audit(p, p.OrgID, "vmware.cbt_cancel", "vmware", r.MOID, ip, map[string]any{"import": id, "state": r.State})
	if j := s.cbtRT().job(id); j != nil {
		j.cancel() // the job stops; cbtRun then cleans up while still owning the import
		return nil
	}
	s.cbtStart(id, "cleanup", func(ctx context.Context, j *cbtJob) {}) // cbtRun sees cancel_req and cleans up
	return nil
}

// ---- the driver ----------------------------------------------------------------

// CBTTick drives every unfinished warm import from its DB state. The worker
// calls it at boot (resume/recover after a restart) and every few seconds:
// due delta passes start, a base copy a restart interrupted starts again, an
// interrupted cut-over drops back to syncing, cleanup is retried until vCenter
// answers. Imports a running job owns are left alone.
func (s *Service) CBTTick() {
	if s.db == nil {
		return
	}
	rt := s.cbtRT()
	rows, err := s.cbtList(`state NOT IN ('done','cancelled','error') ORDER BY created_at`)
	if err != nil {
		log.Printf("vmware-cbt: tick: %v", err)
		return
	}
	now := rt.now().Unix()
	for _, r := range rows {
		id := r.ID
		if rt.job(id) != nil {
			continue
		}
		switch {
		case r.CancelReq && r.State != cbtFinishing:
			s.cbtStart(id, "cleanup", func(ctx context.Context, j *cbtJob) {})
		case r.State == cbtStarting || r.State == cbtBaseCopy:
			if r.NextRun <= now {
				s.cbtStart(id, "base", func(ctx context.Context, j *cbtJob) { s.cbtBaseJob(ctx, j, id) })
			}
		case r.State == cbtSyncing:
			if r.NextRun <= now {
				s.cbtStart(id, "delta", func(ctx context.Context, j *cbtJob) { s.cbtDeltaJob(ctx, j, id) })
			}
		case r.State == cbtCutover:
			// No job owns it: vdxd restarted mid cut-over. The source is never
			// left half-converted — drop back to syncing; the user cuts over again.
			s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, next_run_at=?, step=? WHERE id=? AND state=?`, cbtSyncing, now,
				"the cut-over was interrupted by a vdxd restart — still syncing; start the cut-over again", id, cbtCutover)
		case r.State == cbtFinishing:
			if r.ResultImage != "" {
				s.cbtBeginCleanup(id, cbtDone, "conversion finished before the restart")
			} else {
				s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, next_run_at=?, step=? WHERE id=? AND state=?`, cbtSyncing, now,
					"the conversion was interrupted by a vdxd restart — staging is intact; start the cut-over again", id, cbtFinishing)
			}
		case r.State == cbtCleanup:
			if r.NextRun <= now {
				s.cbtStart(id, "cleanup", func(ctx context.Context, j *cbtJob) {})
			}
		}
	}
}

// cbtFatal marks an error that retrying can't fix.
type cbtFatal struct{ error }

func fatalf(format string, a ...any) error { return cbtFatal{fmt.Errorf(format, a...)} }

// cbtFailed records a failed job. A fatal error, or the cbtMaxFailures-th in a
// row, ends the import in error (after cleanup); anything else is retried
// after cbtRetryDelay. A cancel in progress wins over both.
func (s *Service) cbtFailed(id string, lg *importLogger, what string, err error) {
	r, lerr := s.cbtLoad(id)
	if lerr != nil {
		return
	}
	if r.CancelReq {
		lg.logf("%s stopped: cancel requested", what)
		return
	}
	msg := fmt.Sprintf("%s: %v", what, err)
	var fe cbtFatal
	if errors.As(err, &fe) || r.Fails+1 >= cbtMaxFailures {
		lg.logf("FAILED (giving up): %s", msg)
		s.cbtExec(`UPDATE vmware_cbt_imports SET last_error=?, fail_count=fail_count+1 WHERE id=?`, msg, id)
		s.cbtBeginCleanup(id, cbtError, msg)
		return
	}
	lg.logf("FAILED (will retry in %s): %s", cbtRetryDelay, msg)
	s.cbtExec(`UPDATE vmware_cbt_imports SET last_error=?, fail_count=fail_count+1, next_run_at=?, step=? WHERE id=?`,
		msg, s.cbtRT().now().Add(cbtRetryDelay).Unix(), "retrying after an error", id)
}

// cbtBeginCleanup moves an import to cleanup, landing in end once it succeeds.
func (s *Service) cbtBeginCleanup(id, end, why string) {
	s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, end_state=?, next_run_at=0, step=?, updated_at=datetime('now')
		WHERE id=? AND state NOT IN ('done','cancelled','error')`, cbtCleanup, end, "cleaning up ("+why+")", id)
}

// cbtConnect opens the vSphere session for a job and builds the consent from
// the stored import (consent=1 is the operator's tick of the CBT box).
func (s *Service) cbtConnect(ctx context.Context, r *cbtImport) (cbtSource, vmware.CBTConsent, string, error) {
	if !r.Consent {
		return nil, vmware.CBTConsent{}, "", fatalf("this import carries no CBT consent")
	}
	consent, err := vmware.NewCBTConsent(r.MOID, r.ID)
	if err != nil {
		return nil, vmware.CBTConsent{}, "", cbtFatal{err}
	}
	if r.PassEnc == "" {
		return nil, vmware.CBTConsent{}, "", fatalf("the stored vCenter credentials are gone")
	}
	pass, err := s.encOpen(r.PassEnc)
	if err != nil {
		return nil, vmware.CBTConsent{}, "", fmt.Errorf("unseal vCenter password: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	src, err := s.cbtRT().dial(cctx, vmware.Creds{URL: r.URL, User: r.User, Pass: pass, Insecure: r.Insecure})
	if err != nil {
		return nil, vmware.CBTConsent{}, "", fmt.Errorf("connect to vSphere: %w", err)
	}
	return src, consent, pass, nil
}

// ---- snapshots -------------------------------------------------------------------

// cbtTakeSnapshot records a snapshot under a fresh unique name, THEN creates it
// and records its moref — so a crash at any point leaves a record cleanup can
// resolve. Returns the moref and the record id.
func (s *Service) cbtTakeSnapshot(ctx context.Context, src cbtSource, consent vmware.CBTConsent, r *cbtImport, lg *importLogger) (string, cbtSnapRec, error) {
	s.cbtExec(`UPDATE vmware_cbt_imports SET snap_seq=snap_seq+1 WHERE id=?`, r.ID)
	var seq int
	if err := s.db.QueryRow(`SELECT snap_seq FROM vmware_cbt_imports WHERE id=?`, r.ID).Scan(&seq); err != nil {
		return "", cbtSnapRec{}, err
	}
	short := strings.ReplaceAll(r.ID, "-", "")
	if len(short) > 12 {
		short = short[:12]
	}
	name := fmt.Sprintf("%s%s-%d", vmware.SnapshotPrefix, short, seq)
	now := s.cbtRT().now().Unix()
	res, err := s.db.Exec(`INSERT INTO vmware_cbt_snapshots(import_id,moid,name,created_at) VALUES(?,?,?,?)`, r.ID, r.MOID, name, now)
	if err != nil {
		return "", cbtSnapRec{}, fmt.Errorf("record snapshot: %w", err)
	}
	rec := cbtSnapRec{Name: name, CreatedAt: now}
	rec.ID, _ = res.LastInsertId()
	lg.logf("creating snapshot %s on the source (crash-consistent, no memory; removed after this pass)", name)
	moref, err := src.CreateCBTSnapshot(ctx, consent, name, "Temporary VXVisor warm-migration snapshot (import "+r.ID+"). Removed automatically.")
	if err != nil {
		return "", rec, err
	}
	rec.Moref = moref
	s.cbtExec(`UPDATE vmware_cbt_snapshots SET moref=? WHERE id=?`, moref, rec.ID)
	s.SysAudit(r.OrgID, "vmware.cbt_snapshot_create", "vmware", r.MOID, map[string]any{"import": r.ID, "snapshot": name, "moref": moref})
	return moref, rec, nil
}

// cbtDropSnapshot removes one snapshot we recorded and marks the record. A
// failure leaves the record pending, so the next job or cleanup retries.
func (s *Service) cbtDropSnapshot(ctx context.Context, src cbtSource, consent vmware.CBTConsent, r *cbtImport, rec cbtSnapRec, lg *importLogger) error {
	removed, err := src.RemoveCBTSnapshot(ctx, consent, rec.Moref, rec.Name)
	switch {
	case errors.Is(err, vmware.ErrNotOurSnapshot):
		// Ours by record, but renamed since: someone took it over. Leave it to
		// them rather than remove a snapshot that isn't (any longer) ours.
		lg.logf("NOT removing snapshot %s (%s): %v — remove it in vCenter if it is no longer needed", rec.Name, rec.Moref, err)
		s.cbtExec(`UPDATE vmware_cbt_snapshots SET removed_at=-1 WHERE id=?`, rec.ID)
		s.SysAudit(r.OrgID, "vmware.cbt_snapshot_abandoned", "vmware", r.MOID, map[string]any{"import": r.ID, "snapshot": rec.Name, "moref": rec.Moref, "reason": err.Error()})
		return nil
	case err != nil && !vmware.IsNotFound(err):
		lg.logf("could not remove snapshot %s (%s): %v — will retry", rec.Name, rec.Moref, err)
		return err
	}
	s.cbtExec(`UPDATE vmware_cbt_snapshots SET removed_at=? WHERE id=?`, s.cbtRT().now().Unix(), rec.ID)
	if removed {
		lg.logf("removed snapshot %s", rec.Name)
		s.SysAudit(r.OrgID, "vmware.cbt_snapshot_remove", "vmware", r.MOID, map[string]any{"import": r.ID, "snapshot": rec.Name, "moref": rec.Moref})
	}
	return nil
}

// cbtRemoveLeftovers removes every snapshot this import recorded and has not yet
// removed (a pass a crash or error interrupted). ONLY recorded snapshots are
// touched: by moref when we have it, else by the exact unique name we wrote
// down before the create call. incomplete is true while a record can't be
// resolved yet (a create that may still be finishing on vCenter).
func (s *Service) cbtRemoveLeftovers(ctx context.Context, src cbtSource, consent vmware.CBTConsent, r *cbtImport, lg *importLogger) (incomplete bool, err error) {
	recs, err := s.cbtPendingSnaps(r.ID)
	if err != nil || len(recs) == 0 {
		return false, err
	}
	var st vmware.CBTVMState
	needTree := false
	for _, rec := range recs {
		needTree = needTree || rec.Moref == ""
	}
	if needTree {
		if st, err = src.CBTState(ctx, r.MOID); err != nil {
			if vmware.IsNotFound(err) {
				lg.logf("the source VM no longer exists — its snapshots went with it")
				s.cbtExec(`UPDATE vmware_cbt_snapshots SET removed_at=? WHERE import_id=? AND removed_at=0`, s.cbtRT().now().Unix(), r.ID)
				return false, nil
			}
			return true, err
		}
	}
	for _, rec := range recs {
		if rec.Moref == "" {
			var hits []string
			for _, sn := range st.Snapshots {
				if sn.Name == rec.Name {
					hits = append(hits, sn.MOREF)
				}
			}
			switch {
			case len(hits) > 1:
				lg.logf("snapshot name %s is ambiguous on the source (%d matches) — not removing any of them", rec.Name, len(hits))
				incomplete = true
				continue
			case len(hits) == 0:
				if s.cbtRT().now().Unix()-rec.CreatedAt < int64(cbtOrphanGrace/time.Second) {
					incomplete = true // its create may still be running on vCenter
					continue
				}
				lg.logf("snapshot %s was never created (its create call was interrupted)", rec.Name)
				s.cbtExec(`UPDATE vmware_cbt_snapshots SET removed_at=? WHERE id=?`, s.cbtRT().now().Unix(), rec.ID)
				continue
			}
			rec.Moref = hits[0]
			s.cbtExec(`UPDATE vmware_cbt_snapshots SET moref=? WHERE id=?`, rec.Moref, rec.ID)
		}
		lg.logf("removing leftover snapshot %s (%s)", rec.Name, rec.Moref)
		if derr := s.cbtDropSnapshot(ctx, src, consent, r, rec, lg); derr != nil {
			return true, derr
		}
	}
	return incomplete, nil
}

// ---- jobs --------------------------------------------------------------------------

// cbtBaseJob: record the CBT state we found, enable CBT, snapshot, copy every
// allocated area of every disk into fresh sparse staging, record the change
// ids, remove the snapshot. A retry starts the base copy over.
func (s *Service) cbtBaseJob(ctx context.Context, j *cbtJob, id string) {
	rt := s.cbtRT()
	r, err := s.cbtLoad(id)
	if err != nil || (r.State != cbtStarting && r.State != cbtBaseCopy) {
		return
	}
	lg := s.cbtLogger(id)
	defer lg.close()
	lg.logf("warm import %s: base copy (attempt %d) of %s on %s as %s", id, r.Fails+1, r.MOID, r.Host, r.User)
	s.cbtStep(id, "connecting to vSphere")
	src, consent, pass, err := s.cbtConnect(ctx, r)
	if err != nil {
		s.cbtFailed(id, lg, "connect", err)
		return
	}
	defer src.Close(context.Background())
	if _, err := s.cbtRemoveLeftovers(ctx, src, consent, r, lg); err != nil {
		s.cbtFailed(id, lg, "remove leftover snapshots", err)
		return
	}

	// Everything that can refuse the import is checked BEFORE the source is touched.
	vm, err := src.GetVM(ctx, r.MOID)
	if err != nil {
		if vmware.IsNotFound(err) {
			err = cbtFatal{err}
		}
		s.cbtFailed(id, lg, "inspect source", err)
		return
	}
	s.cbtExec(`UPDATE vmware_cbt_imports SET vm_name=? WHERE id=?`, vm.Name, id)
	st, err := src.CBTState(ctx, r.MOID)
	if err != nil {
		s.cbtFailed(id, lg, "inspect source", err)
		return
	}
	lg.logf("source %q: power=%s CBT=%v disks=%d existing-snapshots=%d", vm.Name, st.PowerState, st.CBTEnabled, len(vm.Disks), len(st.Snapshots))
	if !vm.Importable {
		s.cbtFailed(id, lg, "precheck", fatalf("%s", vm.ImportNote))
		return
	}
	if st.Independent {
		s.cbtFailed(id, lg, "precheck", fatalf("the VM has an independent-mode disk, which snapshots skip — it can't be warm-migrated (use a cold import)"))
		return
	}
	var need int64
	for _, d := range vm.Disks {
		need += d.CapacityGB << 30
	}
	destDir := s.stg.ImageDir()
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		s.cbtFailed(id, lg, "precheck", err)
		return
	}
	if free := s.stg.FreeBytes(destDir); free > 0 && free < need*2 {
		s.cbtFailed(id, lg, "precheck", fatalf("not enough free space in image storage (need ~%d GiB for staging + the converted copy, have %d GiB)", need*2>>30, free>>30))
		return
	}

	// Record CBT as we found it — once, before we ever change it — so it can be
	// put back exactly. Then turn it on (if off): the snapshot below is the stun
	// cycle that activates it.
	if r.CBTOrig < 0 {
		orig := 0
		if st.CBTEnabled {
			orig = 1
		}
		s.cbtExec(`UPDATE vmware_cbt_imports SET cbt_orig=? WHERE id=? AND cbt_orig=-1`, orig, id)
		r.CBTOrig = orig
	}
	if !st.CBTEnabled {
		lg.logf("enabling Changed Block Tracking on the source (operator consent; switched back off at the end)")
		s.cbtExec(`UPDATE vmware_cbt_imports SET cbt_enabled_by_us=1 WHERE id=?`, id)
		if err := src.SetChangeTracking(ctx, consent, true); err != nil {
			s.cbtFailed(id, lg, "enable CBT", err)
			return
		}
		s.SysAudit(r.OrgID, "vmware.cbt_enable", "vmware", r.MOID, map[string]any{"import": id})
	}

	s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, step=? WHERE id=?`, cbtBaseCopy, "snapshotting the source", id)
	snap, rec, err := s.cbtTakeSnapshot(ctx, src, consent, r, lg)
	if err != nil {
		s.cbtFailed(id, lg, "snapshot", err)
		return
	}
	dropped := false
	defer func() {
		if !dropped {
			_ = s.cbtDropSnapshot(context.Background(), src, consent, r, rec, lg)
		}
	}()
	disks, err := src.SnapshotDisks(ctx, r.MOID, snap)
	if err != nil {
		s.cbtFailed(id, lg, "read snapshot disks", err)
		return
	}
	for _, d := range disks {
		if d.ChangeID == "" {
			s.cbtFailed(id, lg, "CBT", fmt.Errorf("CBT is not active on disk %q yet (no change id at the snapshot)", d.Label))
			return
		}
	}

	// Fresh sparse staging, one raw file per disk.
	if _, err := s.db.Exec(`DELETE FROM vmware_cbt_disks WHERE import_id=?`, id); err != nil {
		s.cbtFailed(id, lg, "staging", err)
		return
	}
	files := make([]*os.File, len(disks))
	defer func() {
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	for i, d := range disks {
		path := filepath.Join(destDir, fmt.Sprintf("%s%s-disk%d.raw", cbtStagePrefix, id, i))
		if _, err := s.db.Exec(`INSERT INTO vmware_cbt_disks(import_id,device_key,idx,label,capacity,staging) VALUES(?,?,?,?,?,?)`,
			id, d.Key, i, d.Label, d.Capacity, path); err != nil {
			s.cbtFailed(id, lg, "staging", err)
			return
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o640)
		if err == nil {
			err = f.Truncate(d.Capacity)
		}
		if err != nil {
			s.cbtFailed(id, lg, "staging", err)
			return
		}
		files[i] = f
	}

	// Allocated areas of each disk at the snapshot (change id "*"), then copy.
	areas := make([][]vmware.ChangedArea, len(disks))
	var total int64
	for i, d := range disks {
		a, err := src.QueryChangedAreas(ctx, r.MOID, snap, d.Key, d.Capacity, "*")
		if err != nil {
			s.cbtFailed(id, lg, "query allocated areas", err)
			return
		}
		areas[i] = a
		for _, x := range a {
			total += x.Length
		}
	}
	j.total.Store(total)
	lg.logf("base copy: %d disk(s), %d MiB allocated of %d MiB", len(disks), total>>20, need>>20)
	s.cbtStep(id, "copying the base (the source keeps running)")
	start := rt.now()
	for i, d := range disks {
		lg.logf("  disk %d %q (%s): %d area(s)", i, d.Label, d.FileName, len(areas[i]))
		if err := s.cbtCopyDisk(ctx, src, r, pass, d, snap, files[i], areas[i], true, j); err != nil {
			s.cbtFailed(id, lg, "base copy", err)
			return
		}
	}
	elapsed := rt.now().Sub(start)
	lg.logf("base copy done: %d MiB in %s", total>>20, elapsed.Round(time.Second))

	// Commit: the change ids that staging now matches, and the state.
	now := rt.now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		s.cbtFailed(id, lg, "record base copy", err)
		return
	}
	for _, d := range disks {
		if _, err := tx.Exec(`UPDATE vmware_cbt_disks SET change_id=? WHERE import_id=? AND device_key=?`, d.ChangeID, id, d.Key); err != nil {
			_ = tx.Rollback()
			s.cbtFailed(id, lg, "record base copy", err)
			return
		}
	}
	_, err = tx.Exec(`UPDATE vmware_cbt_imports SET state=?, passes=1, base_bytes=?, last_sync_at=?, next_run_at=?, fail_count=0,
		last_error='', step=?, updated_at=datetime('now') WHERE id=? AND state=?`,
		cbtSyncing, total, now, now+r.Interval, "base copy done — syncing changes", id, cbtBaseCopy)
	if err == nil {
		_, err = tx.Exec(`INSERT OR REPLACE INTO vmware_cbt_passes(import_id,pass,kind,bytes,extents,started_at,finished_at) VALUES(?,1,'base',?,?,?,?)`,
			id, total, countAreas(areas), start.Unix(), now)
	}
	if err == nil {
		err = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if err != nil {
		s.cbtFailed(id, lg, "record base copy", err)
		return
	}
	dropped = true
	_ = s.cbtDropSnapshot(context.Background(), src, consent, r, rec, lg)
	s.SysAudit(r.OrgID, "vmware.cbt_base_done", "vmware", r.MOID, map[string]any{"import": id, "bytes": total})
}

func countAreas(a [][]vmware.ChangedArea) int {
	n := 0
	for _, x := range a {
		n += len(x)
	}
	return n
}

// cbtCopyDisk opens one disk at a snapshot and copies the areas into staging,
// then flushes staging to disk. A cancel aborts reads in flight.
func (s *Service) cbtCopyDisk(ctx context.Context, src cbtSource, r *cbtImport, pass string, d vmware.CBTDisk, snap string, f *os.File, areas []vmware.ChangedArea, fresh bool, j *cbtJob) error {
	if len(areas) == 0 {
		return nil
	}
	h, err := s.cbtRT().open(ctx, src, r, pass, d, snap)
	if err != nil {
		return err
	}
	defer h.close()
	if h.abort != nil {
		stop := context.AfterFunc(ctx, h.abort)
		defer stop()
	}
	if err := cbtCopyExtents(ctx, h.readers, f, areas, fresh, func(n int64) { j.done.Add(n) }); err != nil {
		return err
	}
	return f.Sync()
}

// cbtDeltaJob is one scheduled (or "Sync now") delta pass.
func (s *Service) cbtDeltaJob(ctx context.Context, j *cbtJob, id string) {
	r, err := s.cbtLoad(id)
	if err != nil || r.State != cbtSyncing {
		return
	}
	lg := s.cbtLogger(id)
	defer lg.close()
	src, consent, pass, err := s.cbtConnect(ctx, r)
	if err != nil {
		s.cbtFailed(id, lg, "connect", err)
		return
	}
	defer src.Close(context.Background())
	if _, err := s.cbtRemoveLeftovers(ctx, src, consent, r, lg); err != nil {
		s.cbtFailed(id, lg, "remove leftover snapshots", err)
		return
	}
	s.cbtStep(id, "syncing changes")
	if _, err := s.cbtPass(ctx, j, src, consent, pass, r, lg, "delta"); err != nil {
		s.cbtFailed(id, lg, "delta pass", err)
		return
	}
	s.cbtStep(id, "in sync — next pass on schedule")
}

// cbtPass applies everything that changed since the recorded change ids: take a
// snapshot, query each disk's changed areas since its change id, copy them into
// staging, commit the new change ids, remove the snapshot. Re-running a pass a
// crash interrupted is safe: the old change ids still describe staging, so the
// next query returns a superset.
func (s *Service) cbtPass(ctx context.Context, j *cbtJob, src cbtSource, consent vmware.CBTConsent, pass string, r *cbtImport, lg *importLogger, kind string) (int64, error) {
	rt := s.cbtRT()
	st, err := src.CBTState(ctx, r.MOID)
	if err != nil {
		if vmware.IsNotFound(err) {
			return 0, cbtFatal{err}
		}
		return 0, err
	}
	if !st.CBTEnabled {
		return 0, fatalf("CBT was switched off on the source, so the change history is gone — cancel and start a new warm import")
	}
	recs, err := s.cbtDisks(r.ID)
	if err != nil {
		return 0, err
	}
	snap, rec, err := s.cbtTakeSnapshot(ctx, src, consent, r, lg)
	if err != nil {
		return 0, err
	}
	dropped := false
	defer func() {
		if !dropped {
			_ = s.cbtDropSnapshot(context.Background(), src, consent, r, rec, lg)
		}
	}()
	disks, err := src.SnapshotDisks(ctx, r.MOID, snap)
	if err != nil {
		return 0, err
	}
	if len(disks) != len(recs) {
		return 0, fatalf("the source now has %d disk(s), not %d — its disk layout changed during the warm migration", len(disks), len(recs))
	}
	for i := range disks {
		if disks[i].Key != recs[i].Key || disks[i].Capacity != recs[i].Capacity {
			return 0, fatalf("source disk %d changed (device %d → %d, %d → %d bytes) during the warm migration", i, recs[i].Key, disks[i].Key, recs[i].Capacity, disks[i].Capacity)
		}
		if disks[i].ChangeID == "" {
			return 0, fatalf("source disk %d has no CBT change id any more — CBT was reset", i)
		}
	}
	areas := make([][]vmware.ChangedArea, len(disks))
	var total int64
	for i, d := range disks {
		a, err := src.QueryChangedAreas(ctx, r.MOID, snap, d.Key, d.Capacity, recs[i].ChangeID)
		if err != nil {
			return 0, err
		}
		areas[i] = a
		for _, x := range a {
			total += x.Length
		}
	}
	j.done.Store(0)
	j.total.Store(total)
	start := rt.now()
	for i, d := range disks {
		if len(areas[i]) == 0 {
			continue
		}
		f, err := os.OpenFile(recs[i].Staging, os.O_RDWR, 0)
		if err != nil {
			return 0, fatalf("staging file for disk %d is gone: %v", i, err)
		}
		if fi, _ := f.Stat(); fi == nil || fi.Size() != d.Capacity {
			f.Close()
			return 0, fatalf("staging file for disk %d has the wrong size", i)
		}
		err = s.cbtCopyDisk(ctx, src, r, pass, d, snap, f, areas[i], false, j)
		f.Close()
		if err != nil {
			return 0, err
		}
	}
	now := rt.now()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	for _, d := range disks {
		if _, err := tx.Exec(`UPDATE vmware_cbt_disks SET change_id=? WHERE import_id=? AND device_key=?`, d.ChangeID, r.ID, d.Key); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}
	next := now.Unix() + r.Interval
	if _, err := tx.Exec(`UPDATE vmware_cbt_imports SET passes=passes+1, last_sync_at=?, next_run_at=?, fail_count=0, last_error='',
		updated_at=datetime('now') WHERE id=?`, now.Unix(), next, r.ID); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO vmware_cbt_passes(import_id,pass,kind,bytes,extents,started_at,finished_at)
		VALUES(?,(SELECT passes FROM vmware_cbt_imports WHERE id=?),?,?,?,?,?)`, r.ID, r.ID, kind, total, countAreas(areas), start.Unix(), now.Unix()); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	lg.logf("%s pass: %d MiB in %d area(s), %s", kind, total>>20, countAreas(areas), now.Sub(start).Round(time.Second))
	dropped = true
	_ = s.cbtDropSnapshot(context.Background(), src, consent, r, rec, lg)
	return total, nil
}

// cbtCutoverJob: a pass while the source still runs (shrinks the final one),
// then the source powers off (VMware Tools shutdown if asked, else by the
// operator), the final pass, the conversion + instance, and cleanup.
func (s *Service) cbtCutoverJob(ctx context.Context, j *cbtJob, id string, p *Principal, ip string) {
	rt := s.cbtRT()
	r, err := s.cbtLoad(id)
	if err != nil || r.State != cbtCutover {
		return
	}
	lg := s.cbtLogger(id)
	defer lg.close()
	back := func(why string, err error) {
		msg := why
		if err != nil {
			msg = fmt.Sprintf("%s: %v", why, err)
		}
		lg.logf("cut-over stopped: %s — still syncing", msg)
		s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, last_error=?, next_run_at=?, step=? WHERE id=? AND state IN (?,?)`,
			cbtSyncing, msg, rt.now().Add(cbtRetryDelay).Unix(), "cut-over stopped — still syncing; fix the problem and cut over again", id, cbtCutover, cbtFinishing)
	}
	lg.logf("cut-over requested (shut the guest down for you: %v)", r.ShutdownGuest)
	src, consent, pass, err := s.cbtConnect(ctx, r)
	if err != nil {
		back("connect", err)
		return
	}
	defer src.Close(context.Background())
	if _, err := s.cbtRemoveLeftovers(ctx, src, consent, r, lg); err != nil {
		back("remove leftover snapshots", err)
		return
	}
	st, err := src.CBTState(ctx, r.MOID)
	if err != nil {
		back("read source state", err)
		return
	}
	if st.PowerState != "poweredOff" {
		s.cbtStep(id, "cut-over: one more sync while the source still runs")
		if _, err := s.cbtPass(ctx, j, src, consent, pass, r, lg, "delta"); err != nil {
			if ctx.Err() == nil {
				back("pre-cut-over pass", err)
			}
			return
		}
		switch {
		case !r.ShutdownGuest:
			s.cbtStep(id, "cut-over: waiting for you to power the source VM off in vCenter")
		case !st.ToolsOK:
			lg.logf("VMware Tools is not running in the guest — can't shut it down for you")
			s.cbtStep(id, "cut-over: VMware Tools isn't running in the guest — power the source VM off in vCenter")
		default:
			if err := src.ShutdownGuestOS(ctx, consent); err != nil {
				lg.logf("guest shutdown request failed: %v", err)
				s.cbtStep(id, "cut-over: the guest shutdown request failed — power the source VM off in vCenter")
			} else {
				lg.logf("asked VMware Tools to shut the guest down")
				s.SysAudit(r.OrgID, "vmware.cbt_shutdown_guest", "vmware", r.MOID, map[string]any{"import": id})
				s.cbtStep(id, "cut-over: the guest is shutting down")
			}
		}
		deadline := rt.now().Add(cbtPowerOffWait)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(rt.pollEvery):
			}
			st, err = src.CBTState(ctx, r.MOID)
			if err == nil && st.PowerState == "poweredOff" {
				break
			}
			if rt.now().After(deadline) {
				back(fmt.Sprintf("the source was not powered off within %s", cbtPowerOffWait), nil)
				return
			}
		}
		lg.logf("the source is powered off")
	}

	s.cbtStep(id, "cut-over: final sync (the source is off)")
	if _, err := s.cbtPass(ctx, j, src, consent, pass, r, lg, "final"); err != nil {
		if ctx.Err() == nil {
			back("final pass", err)
		}
		return
	}
	if st, err = src.CBTState(ctx, r.MOID); err != nil || st.PowerState != "poweredOff" {
		back("the source was powered back on during the final sync", err)
		return
	}
	// Past this point a cancel is refused: the conversion runs to the end.
	if s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, step=? WHERE id=? AND state=? AND cancel_req=0`,
		cbtFinishing, "cut-over: converting to the target storage and creating the instance", id, cbtCutover) == 0 {
		return // cancelled meanwhile
	}
	vm, err := src.GetVM(ctx, r.MOID)
	if err != nil {
		back("read source shape", err)
		return
	}
	disks, err := s.cbtDisks(id)
	if err != nil {
		back("read staging", err)
		return
	}
	paths := make([]string, len(disks))
	for i, d := range disks {
		paths[i] = d.Staging
	}
	image, sess, err := rt.finish(id, lg, vm, paths, r, p, ip)
	if err != nil {
		back("conversion", err)
		return
	}
	s.cbtExec(`UPDATE vmware_cbt_imports SET result_image=?, result_session=? WHERE id=?`, image, sess, id)
	lg.logf("cut-over complete: image %q, instance %q", image, sess)
	s.cbtBeginCleanup(id, cbtDone, "cut-over complete")
}

// cbtFinish converts the staging files and creates the instance through the
// same tail as every other import (importDisksToInstance).
func (s *Service) cbtFinish(id string, lg *importLogger, vm vmware.VMInfo, disks []string, r *cbtImport, p *Principal, ip string) (string, string, error) {
	backend, zvolPool, err := s.ResolveDiskTarget(p, r.PoolID)
	if err != nil {
		return "", "", err
	}
	s.vmwimp.set(id, func(st *VMwareImportState) { st.VMName = vm.Name; st.HasLog = true })
	var ferr error
	fail := func(step, msg string) {
		lg.logf("FAILED at %s: %s", step, msg)
		ferr = fmt.Errorf("%s: %s", step, msg)
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.Status = "failed"
			st.Step = step
			st.Err = msg
			st.FinishedAt = time.Now().UnixMilli()
			st.LogTail = lg.tailLines(30)
		})
	}
	image, sess, ok := s.importDisksToInstance(id, lg, vm, disks, r.OSType, backend, zvolPool, r.PoolID, importOverride{}, p, ip, fail)
	if !ok {
		return "", "", ferr
	}
	return image, sess, nil
}

// cbtCleanupJob ends an import that is in cleanup: remove every snapshot we
// recorded, put CBT back the way we found it, delete staging, wipe the stored
// password, land in end_state. If vCenter can't be reached it retries (state
// stays cleanup) — the snapshot records keep until they are resolved.
func (s *Service) cbtCleanupJob(ctx context.Context, id string) {
	rt := s.cbtRT()
	r, err := s.cbtLoad(id)
	if err != nil || r.State != cbtCleanup {
		return
	}
	lg := s.cbtLogger(id)
	defer lg.close()
	retry := func(what string, err error) {
		lg.logf("cleanup: %s: %v — retrying in %s (our snapshots stay recorded until removed)", what, err, cbtCleanupRetry)
		s.cbtExec(`UPDATE vmware_cbt_imports SET next_run_at=?, step=? WHERE id=?`, rt.now().Add(cbtCleanupRetry).Unix(),
			fmt.Sprintf("cleaning up — %s failed, retrying: %v", what, err), id)
	}
	pending, err := s.cbtPendingSnaps(id)
	if err != nil {
		retry("read snapshot records", err)
		return
	}
	restoreCBT := r.CBTByUs && r.CBTOrig == 0
	if len(pending) > 0 || restoreCBT {
		src, consent, _, err := s.cbtConnect(ctx, r)
		if err != nil {
			var fe cbtFatal
			if errors.As(err, &fe) {
				lg.logf("cleanup can't reach the source (%v) — %d recorded snapshot(s) and the CBT setting must be checked by hand", err, len(pending))
				s.SysAudit(r.OrgID, "vmware.cbt_cleanup_incomplete", "vmware", r.MOID, map[string]any{"import": id, "reason": err.Error()})
				pending, restoreCBT = nil, false
			} else {
				retry("connect", err)
				return
			}
		} else {
			defer src.Close(context.Background())
			incomplete, err := s.cbtRemoveLeftovers(ctx, src, consent, r, lg)
			if err != nil || incomplete {
				if err == nil {
					err = fmt.Errorf("a snapshot whose create was interrupted may still appear")
				}
				retry("remove snapshots", err)
				return
			}
			if restoreCBT {
				err := src.SetChangeTracking(ctx, consent, false)
				switch {
				case err == nil:
					lg.logf("Changed Block Tracking switched back off on the source (it was off before the import)")
					s.SysAudit(r.OrgID, "vmware.cbt_restore", "vmware", r.MOID, map[string]any{"import": id, "cbt": "off"})
				case vmware.IsNotFound(err):
					lg.logf("the source VM no longer exists — nothing to restore")
				default:
					retry("restore CBT", err)
					return
				}
				s.cbtExec(`UPDATE vmware_cbt_imports SET cbt_enabled_by_us=0 WHERE id=?`, id)
			}
		}
	}
	disks, _ := s.cbtDisks(id)
	for _, d := range disks {
		if err := os.Remove(d.Staging); err == nil {
			lg.logf("deleted staging %s", filepath.Base(d.Staging))
		}
	}
	end := r.EndState
	if !cbtTerminal(end) {
		end = cbtError
	}
	step := map[string]string{
		cbtDone:      "done — instance created; the source's CBT setting and snapshots are as they were",
		cbtCancelled: "cancelled — our snapshots removed, CBT restored, staging deleted",
		cbtError:     "failed — our snapshots removed, CBT restored, staging deleted",
	}[end]
	s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, end_state='', vc_pass_enc='', step=?, finished_at=datetime('now'), updated_at=datetime('now')
		WHERE id=?`, end, step, id)
	lg.logf("warm import %s: %s", end, step)
	s.SysAudit(r.OrgID, "vmware.cbt_"+end, "vmware", r.MOID, map[string]any{"import": id, "image": r.ResultImage, "instance": r.ResultSession, "error": r.LastErr})
}

// ---- status for the UI ---------------------------------------------------------

// CBTPass is one copy pass, for the per-import history.
type CBTPass struct {
	Pass  int    `json:"pass"`
	Kind  string `json:"kind"`
	Bytes int64  `json:"bytes"`
	Secs  int64  `json:"secs"`
	At    int64  `json:"at"` // unix ms
}

// CBTImportState is one warm import for the poller.
type CBTImportState struct {
	ID          string    `json:"id"`
	VM          string    `json:"vm"`
	MOID        string    `json:"moid"`
	Host        string    `json:"host"`
	State       string    `json:"state"`
	Step        string    `json:"step"`
	Err         string    `json:"err,omitempty"`
	Job         string    `json:"job,omitempty"` // running job: base|delta|cutover|cleanup
	DoneBytes   int64     `json:"done_bytes"`
	TotalBytes  int64     `json:"total_bytes"`
	Rate        int64     `json:"rate"`
	Passes      int       `json:"passes"`
	BaseBytes   int64     `json:"base_bytes"`
	LastSync    int64     `json:"last_sync"` // unix ms
	NextSync    int64     `json:"next_sync"` // unix ms
	IntervalMin int64     `json:"interval_min"`
	CBTOrig     string    `json:"cbt_orig"` // on | off | unknown
	Pending     int       `json:"pending_snapshots"`
	History     []CBTPass `json:"history"`
	CanSync     bool      `json:"can_sync"`
	CanCutover  bool      `json:"can_cutover"`
	CanCancel   bool      `json:"can_cancel"`
	Result      string    `json:"result,omitempty"`
}

// CBTImportStates lists unfinished warm imports and those finished in the last
// week (admin only).
func (s *Service) CBTImportStates(p *Principal) []CBTImportState {
	if !p.IsAdmin || s.db == nil {
		return nil
	}
	rt := s.cbtRT()
	rows, err := s.cbtList(`state NOT IN ('done','cancelled','error') OR finished_at >= datetime('now','-7 days') ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil
	}
	out := make([]CBTImportState, 0, len(rows))
	for _, r := range rows {
		st := CBTImportState{
			ID: r.ID, VM: r.VMName, MOID: r.MOID, Host: r.Host, State: r.State, Step: r.Step, Err: r.LastErr,
			Passes: r.Passes, BaseBytes: r.BaseBytes, LastSync: r.LastSync * 1000, IntervalMin: r.Interval / 60,
			CBTOrig: map[int]string{-1: "unknown", 0: "off", 1: "on"}[r.CBTOrig],
		}
		if st.VM == "" {
			st.VM = r.MOID
		}
		if r.State == cbtSyncing {
			st.NextSync = r.NextRun * 1000
		}
		if r.ResultImage != "" {
			st.Result = r.ResultImage
		}
		j := rt.job(r.ID)
		if j != nil {
			st.Job = j.kind
			st.DoneBytes, st.TotalBytes = j.done.Load(), j.total.Load()
			if el := rt.now().Sub(j.started).Seconds(); el > 1 {
				st.Rate = int64(float64(st.DoneBytes) / el)
			}
		}
		if pend, err := s.cbtPendingSnaps(r.ID); err == nil {
			st.Pending = len(pend)
		}
		st.History = s.cbtHistory(r.ID, 8)
		active := !cbtTerminal(r.State)
		st.CanSync = r.State == cbtSyncing && j == nil && !r.CancelReq
		st.CanCutover = st.CanSync
		st.CanCancel = active && r.State != cbtFinishing && r.State != cbtCleanup && !r.CancelReq
		if r.State == cbtFinishing {
			if t, ok := s.vmwimp.get(r.ID); ok && t.Step != "" {
				st.Step = "cut-over: " + t.Step
			}
		}
		out = append(out, st)
	}
	return out
}

func (s *Service) cbtHistory(id string, n int) []CBTPass {
	rows, err := s.db.Query(`SELECT pass,kind,bytes,started_at,finished_at FROM vmware_cbt_passes WHERE import_id=? ORDER BY pass DESC LIMIT ?`, id, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []CBTPass
	for rows.Next() {
		var p CBTPass
		var started, finished int64
		if rows.Scan(&p.Pass, &p.Kind, &p.Bytes, &started, &finished) == nil {
			p.Secs, p.At = finished-started, finished*1000
			out = append(out, p)
		}
	}
	return out
}

// sweepCBTStaging removes .vdxcbt-* staging files that no unfinished warm import
// owns (an import that ended while its file couldn't be deleted). Boot only.
func (s *Service) sweepCBTStaging() {
	if s.stg == nil || s.db == nil {
		return
	}
	keep := map[string]bool{}
	rows, err := s.db.Query(`SELECT d.staging FROM vmware_cbt_disks d JOIN vmware_cbt_imports i ON i.id=d.import_id
		WHERE i.state NOT IN ('done','cancelled','error')`)
	if err != nil {
		return
	}
	for rows.Next() {
		var p string
		if rows.Scan(&p) == nil {
			keep[p] = true
		}
	}
	rows.Close()
	dir := s.stg.ImageDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() || !strings.HasPrefix(e.Name(), cbtStagePrefix) || keep[full] {
			continue
		}
		if os.Remove(full) == nil {
			log.Printf("vmware-cbt: removed orphaned staging file %s", full)
		}
	}
}
