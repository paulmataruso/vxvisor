package service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/session"
	"vdxclone/internal/store"
)

func TestNextRun(t *testing.T) {
	loc := time.FixedZone("X", 2*3600)
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04:05", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// 2026-10-29 is a Thursday.
	for _, c := range []struct {
		p     SnapshotPolicy
		after string
		want  string
	}{
		{SnapshotPolicy{Schedule: "hourly", AtMinute: 15}, "2026-10-29 10:00:00", "2026-10-29 10:15:00"},
		{SnapshotPolicy{Schedule: "hourly", AtMinute: 15}, "2026-10-29 10:15:00", "2026-10-29 11:15:00"},
		{SnapshotPolicy{Schedule: "hourly", AtMinute: 0}, "2026-10-29 23:59:59", "2026-10-30 00:00:00"},
		{SnapshotPolicy{Schedule: "daily", AtHour: 1, AtMinute: 30}, "2026-10-29 01:29:00", "2026-10-29 01:30:00"},
		{SnapshotPolicy{Schedule: "daily", AtHour: 1, AtMinute: 30}, "2026-10-29 01:30:00", "2026-10-30 01:30:00"},
		{SnapshotPolicy{Schedule: "daily", AtHour: 1, AtMinute: 30}, "2026-12-31 22:00:00", "2027-01-01 01:30:00"},
		{SnapshotPolicy{Schedule: "weekly", Weekday: 4, AtHour: 3}, "2026-10-29 02:00:00", "2026-10-29 03:00:00"}, // same day, later
		{SnapshotPolicy{Schedule: "weekly", Weekday: 4, AtHour: 3}, "2026-10-29 03:00:00", "2026-11-05 03:00:00"}, // just ran
		{SnapshotPolicy{Schedule: "weekly", Weekday: 0, AtHour: 0}, "2026-10-29 12:00:00", "2026-11-01 00:00:00"}, // next Sunday
		{SnapshotPolicy{Schedule: "weekly", Weekday: 3, AtHour: 9}, "2026-10-29 12:00:00", "2026-11-04 09:00:00"}, // Wednesday passed
	} {
		got := nextRun(c.p, at(c.after), loc)
		if !got.Equal(at(c.want)) {
			t.Errorf("%s after %s: got %s want %s", c.p.ScheduleLabel(), c.after, got.In(loc).Format(time.DateTime), c.want)
		}
		if !got.After(at(c.after)) {
			t.Errorf("not strictly after: %v", got)
		}
	}
}

func TestPruneSelect(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	day := func(d int) string { return now.Add(-time.Duration(d) * 24 * time.Hour).UTC().Format(time.RFC3339) }
	// ids 1..6, one per day, newest = id 6 (0 days old) … id 1 (5 days old).
	mk := func() []session.SnapRecord {
		var out []session.SnapRecord
		for i := 1; i <= 6; i++ {
			out = append(out, session.SnapRecord{ID: int64(i), Name: string(rune('a' + i - 1)), CreatedAt: day(6 - i)})
		}
		return out
	}
	ids := func(rs []session.SnapRecord) string {
		var s []string
		for _, r := range rs {
			s = append(s, r.Name)
		}
		return strings.Join(s, "")
	}
	if got := ids(pruneSelect(mk(), 3, 0, now)); got != "cba" {
		t.Errorf("keep last 3: pruned %q", got)
	}
	if got := ids(pruneSelect(mk(), 0, 2, now)); got != "cba" { // ages 3,4,5 days > 2
		t.Errorf("keep 2 days: pruned %q", got)
	}
	// Union: kept while among the last 4 OR at most 1 day old → only ages 4,5 go
	// (an intersection would also drop the 2- and 3-day-old ones).
	if got := ids(pruneSelect(mk(), 4, 1, now)); got != "ba" {
		t.Errorf("keep last 4 + 1 day: pruned %q", got)
	}
	if got := pruneSelect(mk(), 0, 0, now); got != nil {
		t.Errorf("no retention set must keep all, pruned %d", len(got))
	}
	// Locked and clone-pinned snapshots are never pruned.
	s := mk()
	s[0].LockedUntil = now.Add(time.Hour).Format(time.RFC3339)
	s[1].Clones = []session.CloneRef{{ID: "x", Name: "clone"}}
	if got := ids(pruneSelect(s, 1, 0, now)); got != "edc" {
		t.Errorf("locked/cloned: pruned %q", got)
	}
	// Order of the input doesn't matter (ID decides recency).
	r := mk()
	r[0], r[5] = r[5], r[0]
	if got := ids(pruneSelect(r, 3, 0, now)); got != "cba" {
		t.Errorf("shuffled: pruned %q", got)
	}
}

// ---- org scoping / authz -------------------------------------------------

type polEnv struct {
	s          *Service
	orgA, orgB int64
	adminA     *Principal // org admin of A
	memberA    *Principal // plain member of A
	adminB     *Principal // org admin of B
	instAdmin  *Principal // instance admin (provider org)
	vmA, vmB   string
}

func newPolEnv(t *testing.T) polEnv {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := &Service{db: d, store: store.New(d), mgr: session.NewManager(&config.Config{}, d)}
	var e polEnv
	e.s = s
	exec := func(q string, a ...any) int64 {
		t.Helper()
		res, err := d.Exec(q, a...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	e.orgA = exec(`INSERT INTO orgs(name,slug) VALUES('A','a')`)
	e.orgB = exec(`INSERT INTO orgs(name,slug) VALUES('B','b')`)
	uid := exec(`INSERT INTO users(username,password_hash) VALUES('u','x')`)
	exec(`INSERT OR IGNORE INTO images(name,path) VALUES('img','/x')`)
	e.vmA, e.vmB = "aaaaaaaa-vm", "bbbbbbbb-vm"
	exec(`INSERT INTO sessions(id,name,owner_id,org_id,image_name,disk_path) VALUES(?,?,?,?,'img','/d/a')`, e.vmA, "vm-a", uid, e.orgA)
	exec(`INSERT INTO sessions(id,name,owner_id,org_id,image_name,disk_path) VALUES(?,?,?,?,'img','/d/b')`, e.vmB, "vm-b", uid, e.orgB)
	u := &auth.User{ID: uid, Username: "u"}
	e.adminA = &Principal{User: u, OrgID: e.orgA, OrgRole: "admin"}
	e.memberA = &Principal{User: u, OrgID: e.orgA, OrgRole: "member"}
	e.adminB = &Principal{User: u, OrgID: e.orgB, OrgRole: "admin"}
	var def int64
	_ = d.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&def)
	e.instAdmin = &Principal{User: u, OrgID: def, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	return e
}

func vmPolicy(name, vm string) PolicyInput {
	return PolicyInput{Name: name, TargetKind: "vm", TargetVM: vm, Schedule: "daily", AtHour: 2, KeepLast: 7}
}

func TestSnapshotPolicyOrgScoping(t *testing.T) {
	e := newPolEnv(t)
	s := e.s

	// A member can't manage policies at all.
	if _, err := s.CreateSnapshotPolicy(e.memberA, vmPolicy("p", e.vmA), ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("member create: %v", err)
	}
	if _, err := s.ListSnapshotPolicies(e.memberA); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("member list: %v", err)
	}
	// An org admin can't target another org's VM, and can't pick another org.
	if _, err := s.CreateSnapshotPolicy(e.adminA, vmPolicy("p", e.vmB), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org VM target: %v", err)
	}
	in := vmPolicy("p", e.vmA)
	in.OrgID = e.orgB // ignored for a non-instance-admin
	pa, err := s.CreateSnapshotPolicy(e.adminA, in, "")
	if err != nil {
		t.Fatal(err)
	}
	var org int64
	_ = s.db.QueryRow(`SELECT org_id FROM snapshot_policies WHERE id=?`, pa).Scan(&org)
	if org != e.orgA {
		t.Fatalf("policy landed in org %d, want %d", org, e.orgA)
	}
	pb, err := s.CreateSnapshotPolicy(e.adminB, vmPolicy("p", e.vmB), "") // same name, other org: fine
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnapshotPolicy(e.adminA, vmPolicy("p", e.vmA), ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate name in one org: %v", err)
	}

	// Each org admin sees only its own; the instance admin sees both.
	if l, _ := s.ListSnapshotPolicies(e.adminA); len(l) != 1 || l[0].ID != pa {
		t.Fatalf("A sees %+v", l)
	}
	if l, _ := s.ListSnapshotPolicies(e.instAdmin); len(l) != 2 {
		t.Fatalf("instance admin sees %d", len(l))
	}
	// A can't touch B's policy, by any action.
	if err := s.DeleteSnapshotPolicy(e.adminA, pb, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org delete: %v", err)
	}
	if err := s.SetSnapshotPolicyEnabled(e.adminA, pb, false, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org toggle: %v", err)
	}
	if err := s.RunSnapshotPolicyNow(e.adminA, pb, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org run: %v", err)
	}
	if _, err := s.PolicySnapshots(e.adminA, pb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org snapshots: %v", err)
	}
	// The instance admin can manage any org's, and create into a chosen org.
	if err := s.SetSnapshotPolicyEnabled(e.instAdmin, pb, false, ""); err != nil {
		t.Fatal(err)
	}
	in = vmPolicy("ops", e.vmB)
	in.OrgID = e.orgB
	if _, err := s.CreateSnapshotPolicy(e.instAdmin, in, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSnapshotPolicy(e.adminA, pa, ""); err != nil {
		t.Fatal(err)
	}
	// Every mutation is audited.
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'snapshot_policy.%'`).Scan(&n)
	if n != 5 {
		t.Fatalf("audit rows %d, want 5", n)
	}
}

func TestSnapshotPolicyValidation(t *testing.T) {
	e := newPolEnv(t)
	bad := []PolicyInput{
		{Name: "", TargetKind: "org", Schedule: "daily", KeepLast: 1},
		{Name: "x", TargetKind: "host", Schedule: "daily", KeepLast: 1},
		{Name: "x", TargetKind: "org", Schedule: "monthly", KeepLast: 1},
		{Name: "x", TargetKind: "org", Schedule: "daily"},                                     // no retention
		{Name: "x", TargetKind: "org", Schedule: "daily", KeepLast: 3, Immutable: true},       // immutable needs days
		{Name: "x", TargetKind: "org", Schedule: "daily", AtHour: 24, KeepLast: 1},            // bad time
		{Name: "x", TargetKind: "org", Schedule: "weekly", Weekday: 7, KeepLast: 1},           // bad day
		{Name: "x", TargetKind: "folder", TargetFolder: 9999, Schedule: "daily", KeepLast: 1}, // no such folder
		{Name: "x\x01y", TargetKind: "org", Schedule: "daily", KeepLast: 1},
	}
	for i, in := range bad {
		if _, err := e.s.CreateSnapshotPolicy(e.adminA, in, ""); err == nil {
			t.Errorf("case %d accepted: %+v", i, in)
		}
	}
	ok := PolicyInput{Name: "locked", TargetKind: "org", Schedule: "weekly", Weekday: 6, AtHour: 4, KeepDays: 30, Immutable: true}
	if _, err := e.s.CreateSnapshotPolicy(e.adminA, ok, ""); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyTargetsFolderRecursiveAndScoped(t *testing.T) {
	e := newPolEnv(t)
	d := e.s.db
	ex := func(q string, a ...any) int64 {
		res, err := d.Exec(q, a...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	top := ex(`INSERT INTO vm_folders(org_id,name) VALUES(?, 'top')`, e.orgA)
	sub := ex(`INSERT INTO vm_folders(org_id,parent_id,name) VALUES(?,?,'sub')`, e.orgA, top)
	other := ex(`INSERT INTO vm_folders(org_id,name) VALUES(?, 'other')`, e.orgA)
	for _, v := range []struct {
		id      string
		folder  int64
		deleted bool
	}{{"a1000000-vm", top, false}, {"a2000000-vm", sub, false}, {"a3000000-vm", other, false}, {"a4000000-vm", top, true}} {
		ex(`INSERT INTO sessions(id,name,owner_id,org_id,image_name,disk_path,deleted_at) VALUES(?,?,1,?,'img','/d',?)`,
			v.id, v.id, e.orgA, map[bool]any{true: "2026-01-01T00:00:00Z", false: nil}[v.deleted])
		ex(`INSERT INTO vm_folder_members(vm_id,org_id,folder_id) VALUES(?,?,?)`, v.id, e.orgA, v.folder)
	}
	ids, err := e.s.policyTargets(SnapshotPolicy{OrgID: e.orgA, TargetKind: "folder", TargetFolder: top})
	if err != nil || strings.Join(ids, ",") != "a1000000-vm,a2000000-vm" {
		t.Fatalf("folder targets %v %v", ids, err)
	}
	// The same folder id evaluated for another org resolves to nothing.
	if ids, _ := e.s.policyTargets(SnapshotPolicy{OrgID: e.orgB, TargetKind: "folder", TargetFolder: top}); len(ids) != 0 {
		t.Fatalf("cross-org folder resolved %v", ids)
	}
	if ids, _ := e.s.policyTargets(SnapshotPolicy{OrgID: e.orgB, TargetKind: "org"}); strings.Join(ids, ",") != e.vmB {
		t.Fatalf("org targets %v", ids)
	}
	if ids, _ := e.s.policyTargets(SnapshotPolicy{OrgID: e.orgB, TargetKind: "vm", TargetVM: e.vmA}); len(ids) != 0 {
		t.Fatalf("cross-org vm resolved %v", ids)
	}
}

func TestRunDueSnapshotPolicies(t *testing.T) {
	e := newPolEnv(t)
	s := e.s
	ex := func(q string, a ...any) int64 {
		res, err := s.db.Exec(q, a...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	now := time.Now()
	past, future := now.Add(-time.Minute).UTC().Format(time.RFC3339), now.Add(time.Hour).UTC().Format(time.RFC3339)
	empty := ex(`INSERT INTO vm_folders(org_id,name) VALUES(?, 'empty')`, e.orgA)
	due := ex(`INSERT INTO snapshot_policies(org_id,name,target_kind,target_folder,schedule,keep_last,next_run_at) VALUES(?,?,?,?,?,?,?)`,
		e.orgA, "due", "folder", empty, "hourly", 3, past)
	notYet := ex(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule,keep_last,next_run_at) VALUES(?,?,?,?,?,?)`,
		e.orgA, "later", "org", "daily", 3, future)
	off := ex(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule,keep_last,next_run_at,enabled) VALUES(?,?,?,?,?,?,0)`,
		e.orgA, "off", "org", "daily", 3, past)

	if n := s.RunDueSnapshotPolicies(now, true); n != 1 {
		t.Fatalf("ran %d policies, want 1", n)
	}
	var status, next, last string
	_ = s.db.QueryRow(`SELECT last_status, next_run_at, COALESCE(last_run_at,'') FROM snapshot_policies WHERE id=?`, due).Scan(&status, &next, &last)
	if !strings.Contains(status, "no instances") || last == "" {
		t.Fatalf("status %q last %q", status, last)
	}
	if nt, _ := time.Parse(time.RFC3339, next); !nt.After(now) {
		t.Fatalf("next_run_at not advanced: %s", next)
	}
	for _, id := range []int64{notYet, off} {
		var l string
		_ = s.db.QueryRow(`SELECT COALESCE(last_run_at,'') FROM snapshot_policies WHERE id=?`, id).Scan(&l)
		if l != "" {
			t.Fatalf("policy %d ran", id)
		}
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='snapshot_policy.run' AND actor_kind='system' AND org_id=?`, e.orgA).Scan(&n)
	if n != 1 {
		t.Fatalf("run audits %d", n)
	}
	// Not due any more.
	if n := s.RunDueSnapshotPolicies(now, true); n != 0 {
		t.Fatalf("re-ran %d", n)
	}
}

func TestSnapshotOpsOrgScoping(t *testing.T) {
	e := newPolEnv(t)
	s := e.s
	viewerA := &Principal{User: e.adminA.User, OrgID: e.orgA, OrgRole: "viewer"}
	// Org B's admin can't see or act on org A's VM's snapshots.
	if _, err := s.ListSnapshots(e.adminB, e.vmA); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("list: %v", err)
	}
	if _, err := s.CreateSnapshot(e.adminB, e.vmA, "x", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("create: %v", err)
	}
	if err := s.RevertSnapshot(e.adminB, e.vmA, 1, false, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revert: %v", err)
	}
	if err := s.DeleteSnapshot(e.adminB, e.vmA, 1, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.CloneSession(e.adminB, e.vmA, 0, "x", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("clone: %v", err)
	}
	// A viewer can't mutate even in its own org.
	if _, err := s.CreateSnapshot(viewerA, e.vmA, "x", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("viewer create: %v", err)
	}
	if _, err := s.CloneSession(viewerA, e.vmA, 0, "x", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("viewer clone: %v", err)
	}
	// A snapshot id from another VM is not found through this VM.
	if _, err := s.mgr.RecordSnapshot(e.vmB, "b-snap", session.SnapResult{Tag: "snap-1", Backend: "qcow2"}, session.SnapMeta{}); err != nil {
		t.Fatal(err)
	}
	var bid int64
	_ = s.db.QueryRow(`SELECT id FROM snapshots WHERE session_id=?`, e.vmB).Scan(&bid)
	if err := s.DeleteSnapshot(e.adminA, e.vmA, bid, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot id: %v", err)
	}
	// Move guard: a VM with snapshots can't be storage-moved / migrated.
	if err := s.snapshotMoveGuard(e.vmB); err == nil {
		t.Fatal("move guard let a VM with snapshots move")
	}
	if err := s.snapshotMoveGuard(e.vmA); err != nil {
		t.Fatalf("move guard on a clean VM: %v", err)
	}
}
