package raidctl

import (
	"strings"
	"testing"
)

// Sample `storcli /cALL/eALL/sALL show J` output (trimmed to the fields we read):
// one controller, three drives — one online, one failed (UBad), one rebuilding.
const megaSample = `{
  "Controllers": [
    {
      "Command Status": { "Controller": 0, "Status": "Success" },
      "Response Data": {
        "Drive Information": [
          { "EID:Slt": "252:0", "DID": 9,  "State": "Onln", "DG": 0, "Size": "558.406 GB", "Intf": "SAS", "Med": "HDD", "Model": "ST600MM0006", "Sp": "U", "Type": "-" },
          { "EID:Slt": "252:1", "DID": 10, "State": "UBad", "DG": "-", "Size": "558.406 GB", "Intf": "SAS", "Med": "HDD", "Model": "ST600MM0006", "Sp": "D", "Type": "-" },
          { "EID:Slt": "252:2", "DID": 11, "State": "Rbld", "DG": 0, "Size": "558.406 GB", "Intf": "SAS", "Med": "HDD", "Model": "ST600MM0006", "Sp": "U", "Type": "-" }
        ]
      }
    }
  ]
}`

func TestParseMegaRAID(t *testing.T) {
	ctrls := parseMegaRAID([]byte(megaSample), "/usr/bin/perccli64", nil) // nil targets = skip SMART
	if len(ctrls) != 1 {
		t.Fatalf("want 1 controller, got %d", len(ctrls))
	}
	c := ctrls[0]
	if c.Tool != "perccli64" {
		t.Errorf("tool = %q", c.Tool)
	}
	if len(c.Drives) != 3 {
		t.Fatalf("want 3 drives, got %d", len(c.Drives))
	}
	if d := c.Drives[0]; d.Failed || d.Degraded || d.Location != "252:0" || d.Transport != "megaraid,9" || d.Health != "PASSED" {
		t.Errorf("drive0 unexpected: %+v", d)
	}
	if d := c.Drives[1]; !d.Failed || d.Note == "" || d.Transport != "megaraid,10" {
		t.Errorf("drive1 (UBad) should be failed: %+v", d)
	}
	if d := c.Drives[2]; d.Failed || !d.Degraded || d.Transport != "megaraid,11" {
		t.Errorf("drive2 (Rbld) should be degraded, not failed: %+v", d)
	}
}

// Sample `megacli -PDList -aALL` excerpt: one adapter, two drives — one Online,
// one Failed, and the Online one carries a SMART predictive-alert flag.
const megacliSample = `
Adapter #0

Enclosure Device ID: 252
Slot Number: 0
Device Id: 9
Media Type: Hard Disk Device
Raw Size: 558.911 GB [0x45dd2fb0 Sectors]
Firmware state: Online, Spun Up
Inquiry Data:              SEAGATE ST600MM0006     S0M0ABCD
Drive has flagged a S.M.A.R.T alert : No


Enclosure Device ID: 252
Slot Number: 1
Device Id: 10
Media Type: Hard Disk Device
Raw Size: 558.911 GB [0x45dd2fb0 Sectors]
Firmware state: Failed
Inquiry Data:              SEAGATE ST600MM0006     S0M0WXYZ
Drive has flagged a S.M.A.R.T alert : No


Enclosure Device ID: 252
Slot Number: 2
Device Id: 11
Firmware state: Online, Spun Up
Raw Size: 558.911 GB [0x45dd2fb0 Sectors]
Inquiry Data:              SEAGATE ST600MM0006     S0M0PRED
Drive has flagged a S.M.A.R.T alert : Yes
`

func TestParseMegacli(t *testing.T) {
	ctrls := parseMegacli([]byte(megacliSample), "/usr/sbin/megacli", nil)
	if len(ctrls) != 1 {
		t.Fatalf("want 1 controller, got %d", len(ctrls))
	}
	c := ctrls[0]
	if c.Name != "MegaRAID controller #0" || c.Tool != "megacli" {
		t.Errorf("controller = %q tool=%q", c.Name, c.Tool)
	}
	if len(c.Drives) != 3 {
		t.Fatalf("want 3 drives, got %d", len(c.Drives))
	}
	if d := c.Drives[0]; d.Failed || d.Degraded || d.Location != "252:0" || d.Transport != "megaraid,9" || d.Size != "558.911 GB" || d.Model == "" || d.Health != "PASSED" {
		t.Errorf("drive0 unexpected: %+v", d)
	}
	if d := c.Drives[1]; !d.Failed || d.Location != "252:1" || d.Transport != "megaraid,10" {
		t.Errorf("drive1 (Failed) should be failed: %+v", d)
	}
	if d := c.Drives[2]; d.Failed || !d.Degraded || d.Transport != "megaraid,11" {
		t.Errorf("drive2 (SMART alert) should be degraded: %+v", d)
	}
}

// Sample `megacli -LDPDInfo -aALL` excerpt: VD0 = RAID5 of slots 2,3,4;
// VD1 = RAID0 of slot 0.
const ldpdSample = `
Adapter #0
Number of Virtual Disks: 2
Virtual Drive: 0 (Target Id: 0)
Name                :BOOT
RAID Level          : Primary-5, Secondary-0, RAID Level Qualifier-3
Size                : 297.0 GB
State               : Optimal
Span Depth          : 1
Number Of Drives    : 3
PD: 0 Information
Enclosure Device ID: 32
Slot Number: 2
Drive's position: DiskGroup: 0, Span: 0, Arm: 0
PD: 1 Information
Enclosure Device ID: 32
Slot Number: 3
Drive's position: DiskGroup: 0, Span: 0, Arm: 1
PD: 2 Information
Enclosure Device ID: 32
Slot Number: 4
Drive's position: DiskGroup: 0, Span: 0, Arm: 2
Virtual Drive: 1 (Target Id: 1)
Name                :DATA
RAID Level          : Primary-0, Secondary-0, RAID Level Qualifier-0
Size                : 893.75 GB
State               : Optimal
Span Depth          : 1
Number Of Drives    : 1
PD: 0 Information
Enclosure Device ID: 32
Slot Number: 0
Drive's position: DiskGroup: 1, Span: 0, Arm: 0
`

func TestParseMegacliLDPD(t *testing.T) {
	vds := parseMegacliLDPD([]byte(ldpdSample))
	if len(vds) != 2 {
		t.Fatalf("want 2 VDs, got %d", len(vds))
	}
	v0 := vds[0]
	if v0.adapter != 0 || v0.vd.Target != 0 || v0.vd.RAID != "RAID 5" || v0.vd.Size != "297.0 GB" || v0.vd.State != "Optimal" || v0.vd.Name != "BOOT" || v0.vd.Group != 0 {
		t.Errorf("VD0 unexpected: %+v", v0.vd)
	}
	if len(v0.locs) != 3 || v0.locs[0] != "32:2" || v0.locs[2] != "32:4" {
		t.Errorf("VD0 member locs: %v", v0.locs)
	}
	v1 := vds[1]
	if v1.vd.Target != 1 || v1.vd.RAID != "RAID 0" || v1.vd.Group != 1 || len(v1.locs) != 1 || v1.locs[0] != "32:0" {
		t.Errorf("VD1 unexpected: %+v locs=%v", v1.vd, v1.locs)
	}
}

func TestAttachMegacliVDs(t *testing.T) {
	ctrls := parseMegacli([]byte(megacliSample), "/usr/sbin/megacli", nil) // 3 drives: 252:0/1/2
	// Reuse the LDPD sample but remap its enclosure to 252 to match.
	ld := strings.NewReplacer("32:", "252:", "Enclosure Device ID: 32", "Enclosure Device ID: 252").Replace(ldpdSample)
	attachMegacliVDs(ctrls, []byte(ld), map[int]string{0: "/dev/sda", 1: "/dev/sdb"})
	if len(ctrls) != 1 {
		t.Fatalf("want 1 controller, got %d", len(ctrls))
	}
	// megacliSample has slots 0,1,2 (not 3,4), so VD0 (wants 2,3,4) matches only
	// slot 2; VD1 (wants 0) matches slot 0; slot 1 is unconfigured.
	var devs []string
	for _, vd := range ctrls[0].VDisks {
		devs = append(devs, vd.Dev)
	}
	if len(ctrls[0].VDisks) != 3 { // VD0, VD1, Unconfigured
		t.Fatalf("want 3 groups, got %d (%v)", len(ctrls[0].VDisks), devs)
	}
	if ctrls[0].VDisks[0].Dev != "/dev/sda" || ctrls[0].VDisks[0].RAID != "RAID 5" {
		t.Errorf("group0: %+v", ctrls[0].VDisks[0])
	}
	if ctrls[0].VDisks[1].Dev != "/dev/sdb" {
		t.Errorf("group1 dev: %q", ctrls[0].VDisks[1].Dev)
	}
	last := ctrls[0].VDisks[2]
	if last.Name != "Unconfigured" || len(last.Members) != 1 || last.Members[0].Location != "252:1" {
		t.Errorf("unconfigured group: %+v", last)
	}
}

// Sample `ssacli ctrl all show config detail` excerpt.
const hpSample = `
Smart Array P420i in Slot 0 (Embedded)
   Bus Interface: PCI
   Slot: 0

   Array A

      physicaldrive 1I:1:1
         Port: 1I
         Box: 1
         Bay: 1
         Status: OK
         Drive Type: Data Drive
         Interface Type: SAS
         Size: 600 GB
         Model: HP      EG0600FCSPN
         Serial Number: ABC123

      physicaldrive 1I:1:2
         Status: Failed
         Interface Type: SAS
         Size: 600 GB
         Model: HP      EG0600FCSPN
         Serial Number: DEF456

      physicaldrive 1I:1:3
         Status: Predictive Failure
         Size: 600 GB
         Model: HP      EG0600FCSPN
`

func TestParseSmartArray(t *testing.T) {
	ctrls := parseSmartArray([]byte(hpSample), "/usr/sbin/ssacli")
	if len(ctrls) != 1 {
		t.Fatalf("want 1 controller, got %d", len(ctrls))
	}
	c := ctrls[0]
	if c.Name != "Smart Array P420i (Slot 0)" {
		t.Errorf("name = %q", c.Name)
	}
	if len(c.Drives) != 3 {
		t.Fatalf("want 3 drives, got %d", len(c.Drives))
	}
	if d := c.Drives[0]; d.Failed || d.Degraded || d.Health != "PASSED" || d.Location != "1I:1:1" || d.Serial != "ABC123" {
		t.Errorf("drive0 unexpected: %+v", d)
	}
	if d := c.Drives[1]; !d.Failed || d.Health != "FAILED" {
		t.Errorf("drive1 should be failed: %+v", d)
	}
	if d := c.Drives[2]; d.Failed || !d.Degraded {
		t.Errorf("drive2 should be degraded (predictive): %+v", d)
	}
}

// Sample `arcconf GETCONFIG 1 PD` excerpt.
const aacSample = `
Controller information
   Controller Status : Optimal

Physical Device information
   Device #0
      Device is a Hard drive
      State                              : Online
      Total Size                         : 572325 MB
      Model                              : SEAGATE ST600MM0006
      Serial number                      : S0M0ABCD
   Device #1
      Device is a Hard drive
      State                              : Failed
      Total Size                         : 572325 MB
      Model                              : SEAGATE ST600MM0006
      Serial number                      : S0M0WXYZ
`

func TestParseAdaptec(t *testing.T) {
	c := parseAdaptec([]byte(aacSample), "/usr/sbin/arcconf", 1)
	if c == nil {
		t.Fatal("nil controller")
	}
	if len(c.Drives) != 2 {
		t.Fatalf("want 2 drives, got %d", len(c.Drives))
	}
	if d := c.Drives[0]; d.Failed || d.Health != "PASSED" || d.Serial != "S0M0ABCD" {
		t.Errorf("drive0 unexpected: %+v", d)
	}
	if d := c.Drives[1]; !d.Failed || d.Health != "FAILED" {
		t.Errorf("drive1 should be failed: %+v", d)
	}
}

func TestDetectRegexes(t *testing.T) {
	cases := map[string]string{
		"01:00.0 RAID bus controller: Broadcom / LSI MegaRAID SAS-3 3108 [Invader] (rev 02)": "mega",
		"02:00.0 RAID bus controller: Dell PERC H710 Mini (rev 05)":                           "mega",
		"03:00.0 RAID bus controller: Hewlett-Packard Company Smart Array Gen9 Controllers":   "hp",
		"04:00.0 Serial Attached SCSI controller: Adaptec Smart Storage PQI 12G SAS/PCIe 3":   "aac",
	}
	for line, want := range cases {
		switch want {
		case "mega":
			if !reMega.MatchString(line) {
				t.Errorf("reMega missed: %s", line)
			}
		case "hp":
			if !reHPSA.MatchString(line) {
				t.Errorf("reHPSA missed: %s", line)
			}
		case "aac":
			if !reAACR.MatchString(line) {
				t.Errorf("reAACR missed: %s", line)
			}
		}
	}
}
