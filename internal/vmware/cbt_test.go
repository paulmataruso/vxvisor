package vmware

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"
)

// mutatingSelectors are the govmomi calls in cbt.go that change a source VM.
var mutatingSelectors = map[string]bool{
	"Reconfigure": true, "CreateSnapshot": true, "RemoveSnapshot_Task": true, "ShutdownGuest": true,
}

// TestCBTMutationsAreConsentGated checks cbt.go structurally: every function
// that makes a source-mutating call takes a CBTConsent parameter and calls its
// check() BEFORE the first mutating call. A new mutating helper added without a
// consent gate fails here.
func TestCBTMutationsAreConsentGated(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, cbtFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	gated := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var firstMut, firstCheck token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if mutatingSelectors[sel.Sel.Name] && (firstMut == 0 || call.Pos() < firstMut) {
				firstMut = call.Pos()
			}
			if id, ok := sel.X.(*ast.Ident); ok && sel.Sel.Name == "check" && id.Name == "consent" && (firstCheck == 0 || call.Pos() < firstCheck) {
				firstCheck = call.Pos()
			}
			return true
		})
		if firstMut == 0 {
			continue
		}
		hasConsent := false
		for _, fld := range fn.Type.Params.List {
			if id, ok := fld.Type.(*ast.Ident); ok && id.Name == "CBTConsent" {
				for _, n := range fld.Names {
					hasConsent = hasConsent || n.Name == "consent"
				}
			}
		}
		switch {
		case !hasConsent:
			t.Errorf("%s makes a source-mutating call without a `consent CBTConsent` parameter", fn.Name.Name)
		case firstCheck == 0 || firstCheck > firstMut:
			t.Errorf("%s makes a source-mutating call before consent.check()", fn.Name.Name)
		default:
			gated++
		}
	}
	if gated != 4 {
		t.Errorf("found %d consent-gated mutating functions in %s, want 4 (SetChangeTracking, CreateCBTSnapshot, RemoveCBTSnapshot, ShutdownGuestOS)", gated, cbtFile)
	}
}

// vcsimClient starts a simulated vCenter and returns a connected client plus
// two VM morefs (A is the consented one, B a bystander).
func vcsimClient(t *testing.T) (*Client, string, string) {
	t.Helper()
	model := simulator.VPX()
	t.Cleanup(model.Remove)
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	s := model.Service.NewServer()
	t.Cleanup(s.Close)
	ctx := context.Background()
	c, err := Connect(ctx, Creds{URL: s.URL.String(), User: "u", Pass: "p", Insecure: true})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	vms, err := c.ListVMs(ctx)
	if err != nil || len(vms) < 2 {
		t.Fatalf("list: %v (%d VMs)", err, len(vms))
	}
	return c, vms[0].MOID, vms[1].MOID
}

func TestCBTConsentRequired(t *testing.T) {
	c, a, _ := vcsimClient(t)
	ctx := context.Background()
	if _, err := NewCBTConsent("", "imp"); err == nil {
		t.Fatal("a consent without a VM must be refused")
	}
	if _, err := NewCBTConsent(a, " "); err == nil {
		t.Fatal("a consent without an import id must be refused")
	}
	var zero CBTConsent
	if err := c.SetChangeTracking(ctx, zero, true); err == nil {
		t.Error("SetChangeTracking with no consent must be refused")
	}
	if _, err := c.CreateCBTSnapshot(ctx, zero, SnapshotPrefix+"x", ""); err == nil {
		t.Error("CreateCBTSnapshot with no consent must be refused")
	}
	if _, err := c.RemoveCBTSnapshot(ctx, zero, "snapshot-1", SnapshotPrefix+"x"); err == nil {
		t.Error("RemoveCBTSnapshot with no consent must be refused")
	}
	if err := c.ShutdownGuestOS(ctx, zero); err == nil {
		t.Error("ShutdownGuestOS with no consent must be refused")
	}
	st, err := c.CBTState(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if st.CBTEnabled || len(st.Snapshots) != 0 || st.PowerState != "poweredOn" {
		t.Fatalf("refused calls must not have changed the VM: %+v", st)
	}
}

// TestCBTSnapshotLifecycle runs every mutating call against vcsim: CBT on/off,
// create our snapshot, read its frozen disks, remove ONLY ours (a user snapshot
// taken after it — its child — survives), and refuse to remove anything that
// is not exactly our recorded snapshot.
func TestCBTSnapshotLifecycle(t *testing.T) {
	c, a, b := vcsimClient(t)
	ctx := context.Background()
	consent, err := NewCBTConsent(a, "imp1")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetChangeTracking(ctx, consent, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.CBTState(ctx, a); !st.CBTEnabled {
		t.Fatal("CBT should be on")
	}
	if _, err := c.CreateCBTSnapshot(ctx, consent, "user-name", ""); err == nil {
		t.Fatal("a snapshot name without our prefix must be refused")
	}
	ours := SnapshotPrefix + "imp1-1"
	moref, err := c.CreateCBTSnapshot(ctx, consent, ours, "test")
	if err != nil {
		t.Fatal(err)
	}
	disks, err := c.SnapshotDisks(ctx, a, moref)
	if err != nil {
		t.Fatal(err)
	}
	if len(disks) == 0 || disks[0].FileName == "" || disks[0].Capacity <= 0 {
		t.Fatalf("snapshot disks: %+v", disks)
	}
	if _, err := c.SnapshotDisks(ctx, b, moref); err == nil {
		t.Fatal("a snapshot must not be read as another VM's")
	}

	// The operator takes their own snapshot afterwards (a child of ours).
	userTask, err := object.NewVirtualMachine(c.gc.Client, vmRef(a)).CreateSnapshot(ctx, "nightly-backup", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	ui, err := userTask.WaitForResult(ctx)
	if err != nil {
		t.Fatal(err)
	}
	userMoref := ui.Result.(types.ManagedObjectReference).Value

	if _, err := c.RemoveCBTSnapshot(ctx, consent, userMoref, "nightly-backup"); err == nil {
		t.Fatal("removing a snapshot without our prefix must be refused")
	}
	if _, err := c.RemoveCBTSnapshot(ctx, consent, userMoref, ours); err == nil {
		t.Fatal("removing a snapshot whose real name differs from our record must be refused")
	}
	removed, err := c.RemoveCBTSnapshot(ctx, consent, moref, ours)
	if err != nil || !removed {
		t.Fatalf("remove ours: removed=%v err=%v", removed, err)
	}
	st, _ := c.CBTState(ctx, a)
	if len(st.Snapshots) != 1 || st.Snapshots[0].MOREF != userMoref {
		t.Fatalf("only the user's snapshot must remain, got %+v", st.Snapshots)
	}
	if removed, err := c.RemoveCBTSnapshot(ctx, consent, moref, ours); err != nil || removed {
		t.Fatalf("removing an already-gone snapshot: removed=%v err=%v, want false/nil", removed, err)
	}
	if err := c.SetChangeTracking(ctx, consent, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.CBTState(ctx, a); st.CBTEnabled {
		t.Fatal("CBT should be back off")
	}
}

// TestCBTNeverTouchesOtherVMs: consent for VM A cannot reach VM B — even a
// snapshot on B that carries our prefix is not removed through A's consent.
func TestCBTNeverTouchesOtherVMs(t *testing.T) {
	c, a, b := vcsimClient(t)
	ctx := context.Background()
	before, _ := c.CBTState(ctx, b)
	task, err := object.NewVirtualMachine(c.gc.Client, vmRef(b)).CreateSnapshot(ctx, SnapshotPrefix+"other", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := task.WaitForResult(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bSnap := info.Result.(types.ManagedObjectReference).Value

	consent, _ := NewCBTConsent(a, "imp2")
	if err := c.SetChangeTracking(ctx, consent, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateCBTSnapshot(ctx, consent, SnapshotPrefix+"imp2-1", ""); err != nil {
		t.Fatal(err)
	}
	if removed, err := c.RemoveCBTSnapshot(ctx, consent, bSnap, SnapshotPrefix+"other"); removed || err != nil {
		t.Fatalf("B's snapshot via A's consent: removed=%v err=%v, want not found", removed, err)
	}
	after, _ := c.CBTState(ctx, b)
	if after.CBTEnabled != before.CBTEnabled || len(after.Snapshots) != 1 || after.Snapshots[0].MOREF != bSnap || after.PowerState != before.PowerState {
		t.Fatalf("VM B changed: before %+v after %+v", before, after)
	}
}

func TestCBTShutdownGuest(t *testing.T) {
	c, a, _ := vcsimClient(t)
	ctx := context.Background()
	consent, _ := NewCBTConsent(a, "imp3")
	if err := c.ShutdownGuestOS(ctx, consent); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := c.CBTState(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if st.PowerState == "poweredOff" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest shutdown did not power the VM off (%s)", st.PowerState)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.ShutdownGuestOS(ctx, consent); err == nil || !strings.Contains(err.Error(), "guest shutdown") {
		t.Fatalf("shutting down a powered-off VM must fail cleanly, got %v", err)
	}
}
