package vmware

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmware/govmomi/simulator"
)

// TestConnectAndList exercises Connect + ListVMs against the govmomi simulator
// (vcsim). vcsim does NOT implement ExportVm, so the export/convert pipeline is
// validated separately (and against a real vCenter) — this covers the read-only
// inventory path, which is what the UI's connect+list step depends on.
func TestConnectAndList(t *testing.T) {
	model := simulator.VPX()
	defer model.Remove()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	s := model.Service.NewServer()
	defer s.Close()

	ctx := context.Background()
	c, err := Connect(ctx, Creds{URL: s.URL.String(), User: "u", Pass: "p", Insecure: true})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close(ctx)

	vms, err := c.ListVMs(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(vms) == 0 {
		t.Fatal("expected some VMs from vcsim")
	}
	for _, v := range vms {
		if v.MOID == "" || v.Name == "" {
			t.Errorf("VM missing moid/name: %+v", v)
		}
		if v.PowerState == "" {
			t.Errorf("VM %s missing power state", v.Name)
		}
	}
	// GetVM by moid should resolve the same first VM.
	if _, err := c.GetVM(ctx, vms[0].MOID); err != nil {
		t.Errorf("GetVM(%s): %v", vms[0].MOID, err)
	}
}

// forbiddenOps are the source-mutating vSphere operation names. None may appear
// in the package's non-test source — except the four the consented CBT warm
// migration needs (cbtAllowedOps), and those only in cbtFile.
var forbiddenOps = []string{
	"PowerOff", "PowerOn", "Reset", "Suspend", "Standby",
	"Reconfigure", "CreateSnapshot", "RemoveSnapshot", "RevertToSnapshot",
	"MarkAsTemplate", "MarkAsVirtualMachine", "Consolidate",
	"Relocate", "Migrate", "Clone", "Rename",
	"ShutdownGuest", "RebootGuest", "StandbyGuest", "Upgrade",
	"SetCustomValue", "CustomizeVM", ".Import(", "CreateVM",
}

// cbtFile is the ONE file allowed to change a source VM, and cbtAllowedOps the
// only operations it may use (each behind a CBTConsent — see cbt_test.go).
const cbtFile = "cbt.go"

var cbtAllowedOps = map[string]bool{"Reconfigure": true, "CreateSnapshot": true, "RemoveSnapshot": true, "ShutdownGuest": true}

// TestReadOnlyDiscipline enforces the hard safety requirement: the package must
// only ever READ the source. It fails if any source-mutating vSphere operation
// name appears in the non-test source — a whitelist-by-denylist guard so a future
// edit can't accidentally (e.g.) call PowerOff or Reconfigure on a source VM.
// The single exception is cbt.go (the opt-in, consented warm migration), which
// may use only the four operations in cbtAllowedOps — never a power-off, revert,
// disk merge, or anything else in the list.
func TestReadOnlyDiscipline(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	sawCBT := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range forbiddenOps {
			if f == cbtFile && cbtAllowedOps[bad] {
				sawCBT = true
				continue
			}
			if strings.Contains(src, bad) {
				t.Errorf("%s contains forbidden source-mutating op %q — the vmware package must be read-only on the source (only %s may change a source, and only with consent)", f, bad, cbtFile)
			}
		}
	}
	if !sawCBT {
		t.Errorf("%s not found — the allowlist above must name the real file", cbtFile)
	}
}
