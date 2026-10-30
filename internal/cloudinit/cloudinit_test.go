package cloudinit

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestUserDataShape(t *testing.T) {
	c := Config{InstanceID: "id1", Hostname: "web-01", Username: "vdx", Password: "s3cr3t", SSHKey: "ssh-ed25519 AAAAKEY"}
	ud := c.userData()
	for _, want := range []string{"#cloud-config", "name: 'vdx'", "ssh_pwauth: true", "vdx:s3cr3t", "ssh-ed25519 AAAAKEY"} {
		if !strings.Contains(ud, want) {
			t.Errorf("user-data missing %q:\n%s", want, ud)
		}
	}
	if !strings.Contains(c.metaData(), "instance-id: id1") {
		t.Errorf("meta-data missing instance-id")
	}
}

// TestRawUserData: a client-supplied cloud-config is used verbatim, with the
// generated meta-data kept.
func TestRawUserData(t *testing.T) {
	raw := "#cloud-config\nruncmd:\n  - echo hi\n"
	c := Config{InstanceID: "id2", Hostname: "w", Username: "vdx", Password: "pw", RawUserData: raw}
	if got := c.userData(); got != raw {
		t.Errorf("user-data = %q, want the raw document", got)
	}
	if !strings.Contains(c.metaData(), "instance-id: id2") {
		t.Errorf("meta-data missing instance-id")
	}
}

// TestYAMLQuoting guards against a name breaking the document structure.
func TestYAMLQuoting(t *testing.T) {
	if got := yamlStr("a'b"); got != "'a''b'" {
		t.Errorf("yamlStr quoting: got %q", got)
	}
}

// TestBuildSeedISO builds a real ISO and verifies it is labelled CIDATA. Skips
// cleanly on a host without an ISO authoring tool.
func TestBuildSeedISO(t *testing.T) {
	if !Available() {
		t.Skip("no ISO authoring tool installed")
	}
	dir := t.TempDir()
	iso := dir + "/seed.iso"
	if err := BuildSeedISO(dir, iso, Config{InstanceID: "x", Hostname: "h", Username: "vdx", Password: "pw"}); err != nil {
		t.Fatalf("build: %v", err)
	}
	fi, err := os.Stat(iso)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("iso not created: %v", err)
	}
	// The NoCloud data source requires the volume label to be exactly CIDATA.
	if out, err := exec.Command("blkid", "-o", "value", "-s", "LABEL", iso).Output(); err == nil {
		if lbl := strings.TrimSpace(string(out)); lbl != "" && lbl != "CIDATA" {
			t.Errorf("seed volume label = %q, want CIDATA", lbl)
		}
	}
}
