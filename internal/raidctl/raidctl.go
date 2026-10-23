// Package raidctl enumerates the physical drives hidden behind hardware RAID
// controllers (Dell PERC / Broadcom-LSI-Avago MegaRAID, HPE Smart Array,
// Adaptec/Microsemi/Microchip) so that a failed member disk still surfaces on
// the storage page even though the controller never exposes it to the kernel as
// its own /dev node. A plain `smartctl -H /dev/sdX` against such a controller
// only reports the virtual disk and returns "please add '-d megaraid,N'"; the
// real per-drive health lives behind the vendor CLI plus a `smartctl -d` tunnel.
//
// Everything here is READ-ONLY. It shells out to the vendor CLIs when they are
// installed (perccli/storcli, ssacli/hpssacli, arcconf) and to smartctl with the
// matching `-d` transport. Controllers detected via lspci for which no CLI is
// installed are reported as Missing with an install hint, so the admin knows the
// one package to add rather than seeing silence. Callers must gate behind admin.
package raidctl

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Drive is one physical member disk behind a hardware RAID controller.
type Drive struct {
	Controller string `json:"controller"` // human name, e.g. "PERC H710 Mini" or "MegaRAID #0"
	Vendor     string `json:"vendor"`     // Dell PERC / Broadcom MegaRAID / HPE Smart Array / Adaptec
	Location   string `json:"location"`   // vendor slot id, e.g. "252:0" (EID:Slt) or "1I:1:1"
	Model      string `json:"model"`
	Serial     string `json:"serial"`
	Size       string `json:"size"`
	State      string `json:"state"`  // the controller's own term: Online, Failed, Rebuild, Foreign, UBad, Predictive…
	Health     string `json:"health"` // SMART overall-health via -d passthrough: PASSED | FAILED | unknown
	Failed     bool   `json:"failed"` // hard failure (controller says dead, or SMART FAILED)
	Degraded   bool   `json:"degraded"` // rebuilding / predictive-failure — warn, not dead
	Note       string `json:"note"`   // human reason for failed/degraded
	Transport  string `json:"transport"` // the smartctl -d arg used, e.g. "megaraid,9" (debug/info)
}

// VDisk is a virtual disk (logical drive / disk group) the controller presents
// to the kernel as a single /dev node, backed by one or more physical member
// drives.
type VDisk struct {
	Name    string  `json:"name"`   // controller's label for it, e.g. "BOOT" ("" if none)
	Target  int     `json:"target"` // controller Target Id (maps to the SCSI target → /dev node)
	Group   int     `json:"group"`  // disk-group number
	RAID    string  `json:"raid"`   // "RAID 5", "RAID 0", "RAID 10", "—" for unconfigured
	Size    string  `json:"size"`
	State   string  `json:"state"` // controller's VD state, e.g. "Optimal"
	Dev     string  `json:"dev"`   // /dev/sdX this VD appears as ("" if unresolved)
	Members []Drive `json:"members"`
}

// Controller is one detected RAID adapter and the drives behind it.
type Controller struct {
	Vendor string  `json:"vendor"`
	Name   string  `json:"name"`
	Tool   string  `json:"tool"`   // the CLI binary used to enumerate it
	Drives []Drive `json:"drives"` // flat list of ALL member drives (alerts + fallback)
	VDisks []VDisk `json:"vdisks"` // members grouped by virtual disk (when the backend provides it)
}

// Missing is a RAID adapter seen on the PCI bus whose management CLI is not
// installed, so its member drives can't be read. Surfaced as an install hint.
type Missing struct {
	Vendor string `json:"vendor"`
	PCI    string `json:"pci"`  // the lspci description line
	Hint   string `json:"hint"` // which package/tool to install
}

// Report is the full controller inventory.
type Report struct {
	Controllers []Controller `json:"controllers"`
	Missing     []Missing    `json:"missing"`
}

func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// have reports the first of the candidate binaries that is on PATH.
func have(cands ...string) string {
	for _, c := range cands {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// ---- cache ---------------------------------------------------------------
// The storage page and the /api/drive-alerts poller both read this, so a short
// TTL keeps a burst of polls from re-shelling the vendor CLI (which can be slow)
// on every request.
var (
	cacheMu sync.Mutex
	cached  *Report
	cachedAt time.Time
)

const cacheTTL = 12 * time.Second

// Enumerate returns the controller inventory, cached for a few seconds.
func Enumerate() Report {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cached != nil && time.Since(cachedAt) < cacheTTL {
		return *cached
	}
	r := enumerate()
	cached = &r
	cachedAt = time.Now()
	return r
}

// Available reports whether any RAID controller is present on the host (whether
// or not its CLI is installed) — used to decide if the UI section is relevant.
func Available() bool {
	r := Enumerate()
	return len(r.Controllers) > 0 || len(r.Missing) > 0
}

func enumerate() Report {
	var rep Report
	pci := detectControllers()
	// MegaRAID / PERC — Broadcom/LSI/Avago, rebranded by Dell (PERC) and Lenovo.
	if pci.megaraid {
		if tool := have("perccli64", "perccli", "storcli64", "storcli"); tool != "" {
			rep.Controllers = append(rep.Controllers, megaraidControllers(tool)...)
		} else if tool := have("megacli", "MegaCli64", "MegaCli"); tool != "" {
			rep.Controllers = append(rep.Controllers, megacliControllers(tool)...)
		} else {
			rep.Missing = append(rep.Missing, Missing{
				Vendor: "Broadcom MegaRAID / Dell PERC",
				PCI:    pci.megaraidDesc,
				Hint:   "install megacli (from the hwraid apt repo) or perccli/storcli to read per-drive SMART health",
			})
		}
	}
	// HPE Smart Array.
	if pci.smartarray {
		if tool := have("ssacli", "hpssacli", "hpacucli"); tool != "" {
			rep.Controllers = append(rep.Controllers, smartArrayControllers(tool)...)
		} else {
			rep.Missing = append(rep.Missing, Missing{
				Vendor: "HPE Smart Array",
				PCI:    pci.smartarrayDesc,
				Hint:   "install ssacli (HPE Smart Storage Administrator CLI) to read per-drive health",
			})
		}
	}
	// Adaptec / Microsemi / Microchip.
	if pci.adaptec {
		if tool := have("arcconf"); tool != "" {
			rep.Controllers = append(rep.Controllers, adaptecControllers(tool)...)
		} else {
			rep.Missing = append(rep.Missing, Missing{
				Vendor: "Adaptec / Microchip",
				PCI:    pci.adaptecDesc,
				Hint:   "install arcconf (Microchip maxView CLI) to read per-drive health",
			})
		}
	}
	return rep
}

// ---- controller detection (lspci) ---------------------------------------

type pciHits struct {
	megaraid, smartarray, adaptec                   bool
	megaraidDesc, smartarrayDesc, adaptecDesc       string
}

var (
	reMega = regexp.MustCompile(`(?i)megaraid|\bPERC\b|LSI.*(RAID|SAS)|Broadcom.*(RAID|SAS)|Avago`)
	reHPSA = regexp.MustCompile(`(?i)smart array|hewlett.?packard.*(array|raid)|\bHPE?\b.*smart`)
	reAACR = regexp.MustCompile(`(?i)adaptec|microsemi|pmc.?sierra|microchip.*(raid|smart)|series 8`)
)

func detectControllers() pciHits {
	var h pciHits
	out, err := run("lspci")
	if err != nil {
		return h
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case reMega.MatchString(line):
			h.megaraid, h.megaraidDesc = true, trimPCI(line)
		case reHPSA.MatchString(line):
			h.smartarray, h.smartarrayDesc = true, trimPCI(line)
		case reAACR.MatchString(line):
			h.adaptec, h.adaptecDesc = true, trimPCI(line)
		}
	}
	return h
}

// trimPCI drops the leading "01:00.0 " PCI address for a cleaner description.
func trimPCI(line string) string {
	if i := strings.Index(line, " "); i > 0 && i < 12 {
		return strings.TrimSpace(line[i+1:])
	}
	return line
}

// ---- MegaRAID / PERC (storcli / perccli) ---------------------------------

// megaraid JSON shape from `<tool> /cALL/eALL/sALL show J`.
type mrTop struct {
	Controllers []struct {
		CmdStatus struct {
			Controller int    `json:"Controller"`
			Status     string `json:"Status"`
		} `json:"Command Status"`
		ResponseData struct {
			Drives []map[string]any `json:"Drive Information"`
		} `json:"Response Data"`
	} `json:"Controllers"`
}

func megaraidControllers(tool string) []Controller {
	out, err := run(tool, "/cALL/eALL/sALL", "show", "J")
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseMegaRAID(out, tool, discoverSATargets())
}

// parseMegaRAID turns storcli/perccli JSON into controllers. Split out for tests.
// targets are candidate /dev nodes on which to attempt the `-d megaraid,DID`
// SMART tunnel (nil skips SMART, leaving Health="unknown").
func parseMegaRAID(jsonOut []byte, tool string, targets []string) []Controller {
	var top mrTop
	if err := json.Unmarshal(jsonOut, &top); err != nil {
		return nil
	}
	var ctrls []Controller
	for _, c := range top.Controllers {
		if len(c.ResponseData.Drives) == 0 {
			continue
		}
		cn := c.CmdStatus.Controller
		ctrl := Controller{Vendor: "Broadcom MegaRAID / Dell PERC", Name: "MegaRAID controller #" + itoa(cn), Tool: baseName(tool)}
		smTarget, smTried := "", false // resolve the passthrough target once per controller
		for _, dm := range c.ResponseData.Drives {
			d := Drive{
				Controller: ctrl.Name,
				Vendor:     ctrl.Vendor,
				Location:   mstr(dm, "EID:Slt"),
				Model:      strings.TrimSpace(mstr(dm, "Model")),
				State:      mstr(dm, "State"),
				Size:       mstr(dm, "Size"),
				Health:     "unknown",
			}
			did := mnum(dm, "DID")
			classifyMegaState(&d)
			// SMART tunnel: megaraid device id == DID.
			if did >= 0 {
				arg := "megaraid," + itoa(did)
				d.Transport = arg
				if targets != nil {
					if !smTried {
						smTarget, smTried = resolveMegaTarget(targets, arg), true
					}
					if smTarget != "" {
						applySmart(&d, smartHealthVia(smTarget, arg))
					}
				}
			}
			ctrl.Drives = append(ctrl.Drives, d)
		}
		ctrls = append(ctrls, ctrl)
	}
	return ctrls
}

// classifyMegaState maps a MegaRAID PD state to failed/degraded + a note.
// Onln/Optl/UGood/JBOD/GHS/DHS = healthy; UBad/Offln/Failed/Msng = dead;
// Rbld/Cpybck = rebuilding (degraded).
func classifyMegaState(d *Drive) {
	switch strings.ToLower(strings.TrimSpace(d.State)) {
	case "ubad", "offln", "offline", "failed", "msng", "missing", "bad":
		d.Failed, d.Note = true, "controller reports the drive as "+d.State+" (failed / offline)"
	case "rbld", "rebuild", "rebuilding", "cpybck", "copyback":
		d.Degraded, d.Note = true, "drive is rebuilding — the array is degraded"
	default:
		healthyByController(d) // controller vouches for it (smartctl may refine below)
	}
}

// healthyByController marks a drive PASSED on the controller's say-so when
// smartctl passthrough hasn't given a verdict. Older PERC/MegaRAID firmware
// can't tunnel SMART `-H` for SATA drives ("ATA return descriptor not
// supported"), so the firmware state is the authoritative health signal.
func healthyByController(d *Drive) {
	if d.Health == "" || d.Health == "unknown" {
		d.Health = "PASSED"
	}
}

// applySmart folds a SMART verdict into a drive without overriding a hard
// controller-reported failure.
func applySmart(d *Drive, health string) {
	if health != "" {
		d.Health = health
	}
	if health == "FAILED" && !d.Failed {
		d.Failed, d.Note = true, "SMART overall-health self-assessment: FAILED"
	}
}

// resolveMegaTarget returns the first candidate device that answers the given
// `-d megaraid,N` tunnel (i.e. is a VD on this controller), or "".
func resolveMegaTarget(targets []string, arg string) string {
	for _, t := range targets {
		if smartHealthVia(t, arg) != "" {
			return t
		}
	}
	return ""
}

// discoverSATargets lists candidate SCSI/SATA disk nodes to use as the smartctl
// tunnel target (the controller routes `-d megaraid,N` through any VD node).
func discoverSATargets() []string {
	g, _ := filepath.Glob("/dev/sd[a-z]")
	return g
}

// smartHealthVia runs `smartctl -H -d <arg> <dev>` and returns PASSED/FAILED,
// or "" when the device/transport doesn't answer (so the caller can try another).
func smartHealthVia(dev, dArg string) string {
	out, _ := run("smartctl", "-H", "-d", dArg, dev)
	s := string(out)
	switch {
	case strings.Contains(s, "FAILED"), strings.Contains(s, "FAILING"):
		return "FAILED"
	case strings.Contains(s, "PASSED"), strings.Contains(s, "SMART overall-health self-assessment test result: OK"), strings.Contains(s, "SMART Health Status: OK"):
		return "PASSED"
	}
	return ""
}

// ---- MegaRAID / PERC (megacli — older text CLI from the hwraid apt repo) --

func megacliControllers(tool string) []Controller {
	out, err := run(tool, "-PDList", "-aALL", "-NoLog")
	if err != nil || len(out) == 0 {
		return nil
	}
	ctrls := parseMegacli(out, tool, discoverSATargets())
	// Group the flat member list by virtual disk, and resolve each VD to its
	// /dev node (HCTL target == VD Target Id), so the UI can show "32:2–4 →
	// /dev/sda · RAID 5". Best-effort: on any error the flat list still stands.
	if ld, err := run(tool, "-LDPDInfo", "-aALL", "-NoLog"); err == nil && len(ld) > 0 {
		attachMegacliVDs(ctrls, ld, scsiDevByTarget())
	}
	return ctrls
}

var (
	reMcVD      = regexp.MustCompile(`(?i)^Virtual Drive:\s*(\d+)\s*\(Target Id:\s*(\d+)\)`)
	reMcRAID    = regexp.MustCompile(`(?i)Primary-(\d+),\s*Secondary-(\d+)`)
	reMcGroup   = regexp.MustCompile(`(?i)DiskGroup:\s*(\d+)`)
	reCtrlNum   = regexp.MustCompile(`#(\d+)`)
)

type vdInfo struct {
	adapter int
	vd      VDisk
	locs    []string // member locations (EID:Slt) to match against the flat list
}

// parseMegacliLDPD parses `megacli -LDPDInfo -aALL` into per-adapter virtual
// disks plus the member locations under each. Split out for tests.
func parseMegacliLDPD(out []byte) []vdInfo {
	var res []vdInfo
	adapter := 0
	var cur *vdInfo
	spanDepth := 1
	pendingEID := ""
	flush := func() {
		if cur != nil {
			res = append(res, *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if m := reMcAdapter.FindStringSubmatch(line); m != nil {
			flush()
			adapter = atoiDefault(m[1], 0)
			continue
		}
		if m := reMcVD.FindStringSubmatch(line); m != nil {
			flush()
			cur = &vdInfo{adapter: adapter, vd: VDisk{Target: atoiDefault(m[2], -1)}}
			spanDepth = 1
			continue
		}
		if cur == nil {
			continue
		}
		if m := reMcGroup.FindStringSubmatch(line); m != nil {
			cur.vd.Group = atoiDefault(m[1], 0)
		}
		m := reMcKV.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
		switch {
		case k == "name":
			cur.vd.Name = v
		case k == "raid level":
			if rm := reMcRAID.FindStringSubmatch(v); rm != nil {
				cur.vd.RAID = raidLevelName(atoiDefault(rm[1], -1), atoiDefault(rm[2], 0), spanDepth)
			}
		case k == "span depth", k == "number of spans":
			spanDepth = atoiDefault(v, 1)
			cur.vd.RAID = reRAID(cur.vd.RAID, spanDepth) // refine RAID10 once span known
		case k == "size":
			cur.vd.Size = v
		case k == "state":
			cur.vd.State = v
		case k == "enclosure device id":
			pendingEID = v
		case k == "slot number":
			if pendingEID != "" {
				cur.locs = append(cur.locs, pendingEID+":"+v)
			} else {
				cur.locs = append(cur.locs, v)
			}
			pendingEID = ""
		}
	}
	flush()
	return res
}

// raidLevelName turns MegaRAID "Primary-P, Secondary-S" (+ span depth) into a
// human label.
func raidLevelName(primary, secondary, spanDepth int) string {
	switch primary {
	case 0:
		return "RAID 0"
	case 1:
		if spanDepth > 1 {
			return "RAID 10"
		}
		return "RAID 1"
	case 5:
		if spanDepth > 1 {
			return "RAID 50"
		}
		return "RAID 5"
	case 6:
		if spanDepth > 1 {
			return "RAID 60"
		}
		return "RAID 6"
	case -1:
		return ""
	default:
		return "RAID " + itoa(primary)
	}
}

// reRAID upgrades a bare RAID1/5/6 to its spanned form once the span depth is
// known (the span line can follow the RAID-level line).
func reRAID(cur string, spanDepth int) string {
	if spanDepth <= 1 {
		return cur
	}
	switch cur {
	case "RAID 1":
		return "RAID 10"
	case "RAID 5":
		return "RAID 50"
	case "RAID 6":
		return "RAID 60"
	}
	return cur
}

// attachMegacliVDs folds parsed VD info into the controllers (matched by adapter
// number), resolving each VD's /dev node and pulling its member drives from the
// flat list. Members in no VD land in a trailing "Unconfigured" group.
func attachMegacliVDs(ctrls []Controller, ldOut []byte, devByTarget map[int]string) {
	vds := parseMegacliLDPD(ldOut)
	for ci := range ctrls {
		adn := -1
		if m := reCtrlNum.FindStringSubmatch(ctrls[ci].Name); m != nil {
			adn = atoiDefault(m[1], -1)
		}
		byLoc := map[string]Drive{}
		for _, d := range ctrls[ci].Drives {
			byLoc[d.Location] = d
		}
		used := map[string]bool{}
		for _, vi := range vds {
			if vi.adapter != adn {
				continue
			}
			vd := vi.vd
			if dev, ok := devByTarget[vd.Target]; ok {
				vd.Dev = dev
			}
			for _, loc := range vi.locs {
				if d, ok := byLoc[loc]; ok {
					vd.Members = append(vd.Members, d)
					used[loc] = true
				}
			}
			ctrls[ci].VDisks = append(ctrls[ci].VDisks, vd)
		}
		var un []Drive
		for _, d := range ctrls[ci].Drives {
			if !used[d.Location] {
				un = append(un, d)
			}
		}
		if len(un) > 0 {
			ctrls[ci].VDisks = append(ctrls[ci].VDisks, VDisk{Name: "Unconfigured", RAID: "—", Members: un})
		}
	}
}

// scsiDevByTarget maps a SCSI target id to its /dev node via `lsblk -S` HCTL
// (host:channel:target:lun). For a MegaRAID controller the target id equals the
// VD Target Id. Multi-controller hosts can in theory collide on target id; the
// RAID grouping stays correct regardless, only the /dev label may be approximate.
func scsiDevByTarget() map[int]string {
	out := map[int]string{}
	b, err := run("lsblk", "-S", "-n", "-o", "NAME,HCTL")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		hctl := strings.Split(f[1], ":")
		if len(hctl) < 4 {
			continue
		}
		if t := atoiDefault(hctl[2], -1); t >= 0 {
			out[t] = "/dev/" + f[0]
		}
	}
	return out
}

var (
	reMcAdapter = regexp.MustCompile(`(?i)^Adapter\s*#?(\d+)`)
	reMcKV      = regexp.MustCompile(`^(.+?)\s*:\s*(.+?)\s*$`)
)

// parseMegacli parses `megacli -PDList -aALL` text into controllers. Split out
// for tests; targets nil skips the SMART tunnel.
func parseMegacli(out []byte, tool string, targets []string) []Controller {
	var ctrls []Controller
	var cur *Controller
	var d *Drive
	pendingEID := "" // "Enclosure Device ID" precedes the "Slot Number" that starts a drive
	did := -1
	smTarget, smTried := "", false
	flush := func() {
		if cur == nil || d == nil {
			d, did = nil, -1
			return
		}
		classifyMegaFW(d)
		if did >= 0 {
			arg := "megaraid," + itoa(did)
			d.Transport = arg
			if targets != nil {
				if !smTried {
					smTarget, smTried = resolveMegaTarget(targets, arg), true
				}
				if smTarget != "" {
					applySmart(d, smartHealthVia(smTarget, arg))
				}
			}
		}
		cur.Drives = append(cur.Drives, *d)
		d, did = nil, -1
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if m := reMcAdapter.FindStringSubmatch(line); m != nil {
			flush()
			if cur != nil {
				ctrls = append(ctrls, *cur)
			}
			cur = &Controller{Vendor: "Broadcom MegaRAID / Dell PERC", Name: "MegaRAID controller #" + m[1], Tool: baseName(tool)}
			continue
		}
		m := reMcKV.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		k, v := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
		switch {
		case k == "enclosure device id":
			pendingEID = v // belongs to the slot block that follows
		case k == "slot number":
			flush() // a slot number begins a new physical-drive block
			d = &Drive{Health: "unknown"}
			if cur != nil {
				d.Controller, d.Vendor = cur.Name, cur.Vendor
			}
			if pendingEID != "" {
				d.Location = pendingEID + ":" + v
			} else {
				d.Location = v
			}
			pendingEID = ""
		case d == nil:
			// not inside a drive block yet
		case k == "device id":
			did = atoiDefault(v, -1)
		case k == "firmware state":
			d.State = v
		case k == "raw size":
			if i := strings.Index(v, "["); i > 0 {
				v = strings.TrimSpace(v[:i])
			}
			d.Size = v
		case k == "inquiry data":
			d.Model = strings.Join(strings.Fields(v), " ")
		case strings.HasPrefix(k, "drive has flagged a s.m.a.r.t"):
			if strings.EqualFold(v, "Yes") && !d.Failed {
				d.Degraded = true
				if d.Note == "" {
					d.Note = "drive has flagged a SMART alert — predictive failure"
				}
			}
		}
	}
	flush()
	if cur != nil {
		ctrls = append(ctrls, *cur)
	}
	return ctrls
}

// classifyMegaFW maps a megacli "Firmware state" to failed/degraded + a note.
func classifyMegaFW(d *Drive) {
	s := strings.ToLower(d.State)
	switch {
	case strings.Contains(s, "rebuild"), strings.Contains(s, "copyback"):
		d.Degraded, d.Note = true, "drive is rebuilding — the array is degraded"
	case strings.Contains(s, "fail"), strings.Contains(s, "offline"), strings.Contains(s, "unconfigured(bad)"), strings.Contains(s, "missing"):
		d.Failed, d.Note = true, "controller reports firmware state "+strings.TrimSpace(d.State)+" (failed / offline)"
	default:
		healthyByController(d)
	}
}

// ---- HPE Smart Array (ssacli) --------------------------------------------

func smartArrayControllers(tool string) []Controller {
	out, err := run(tool, "ctrl", "all", "show", "config", "detail")
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseSmartArray(out, tool)
}

var (
	reHPCtrl  = regexp.MustCompile(`(?i)^Smart Array (\S+) in Slot (\S+)`)
	reHPPD    = regexp.MustCompile(`(?i)^physicaldrive\s+(\S+)`)
	reKV      = regexp.MustCompile(`^(.+?):\s*(.+?)\s*$`)
)

func parseSmartArray(out []byte, tool string) []Controller {
	var ctrls []Controller
	var cur *Controller
	var d *Drive
	flush := func() {
		if cur != nil && d != nil {
			classifyHPState(d)
			cur.Drives = append(cur.Drives, *d)
		}
		d = nil
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if m := reHPCtrl.FindStringSubmatch(line); m != nil {
			flush()
			if cur != nil {
				ctrls = append(ctrls, *cur)
			}
			cur = &Controller{Vendor: "HPE Smart Array", Name: "Smart Array " + m[1] + " (Slot " + m[2] + ")", Tool: baseName(tool)}
			continue
		}
		if m := reHPPD.FindStringSubmatch(line); m != nil {
			flush()
			d = &Drive{Location: m[1], Health: "unknown"}
			if cur != nil {
				d.Controller, d.Vendor = cur.Name, cur.Vendor
			}
			continue
		}
		if d == nil {
			continue
		}
		if m := reKV.FindStringSubmatch(line); m != nil {
			k, v := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
			switch {
			case k == "status":
				d.State = v
			case k == "size":
				d.Size = v
			case k == "model":
				d.Model = v
			case strings.HasPrefix(k, "serial"):
				d.Serial = v
			}
		}
	}
	flush()
	if cur != nil {
		ctrls = append(ctrls, *cur)
	}
	return ctrls
}

func classifyHPState(d *Drive) {
	s := strings.ToLower(d.State)
	switch {
	case strings.Contains(s, "predictive"):
		d.Degraded, d.Note = true, "predictive failure — the drive is expected to fail"
	case strings.Contains(s, "rebuild"):
		d.Degraded, d.Note = true, "drive is rebuilding — the array is degraded"
	case strings.Contains(s, "fail"):
		d.Failed, d.Health, d.Note = true, "FAILED", "controller reports the drive status as "+d.State
	case strings.Contains(s, "ok"):
		d.Health = "PASSED"
	}
}

// ---- Adaptec / Microchip (arcconf) ---------------------------------------

func adaptecControllers(tool string) []Controller {
	var ctrls []Controller
	for c := 1; c <= 2; c++ {
		out, err := run(tool, "GETCONFIG", itoa(c), "PD")
		if err != nil || len(out) == 0 {
			continue
		}
		if ct := parseAdaptec(out, tool, c); ct != nil {
			ctrls = append(ctrls, *ct)
		}
	}
	return ctrls
}

var (
	reAACDev = regexp.MustCompile(`(?i)^Device #(\d+)`)
)

func parseAdaptec(out []byte, tool string, cnum int) *Controller {
	ctrl := &Controller{Vendor: "Adaptec / Microchip", Name: "Adaptec controller " + itoa(cnum), Tool: baseName(tool)}
	var d *Drive
	flush := func() {
		if d != nil && (d.State != "" || d.Model != "") {
			classifyAACState(d)
			ctrl.Drives = append(ctrl.Drives, *d)
		}
		d = nil
	}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if m := reAACDev.FindStringSubmatch(line); m != nil {
			flush()
			d = &Drive{Controller: ctrl.Name, Vendor: ctrl.Vendor, Location: "Device #" + m[1], Health: "unknown"}
			continue
		}
		if d == nil {
			continue
		}
		if m := reKV.FindStringSubmatch(line); m != nil {
			k, v := strings.ToLower(strings.TrimSpace(m[1])), strings.TrimSpace(m[2])
			switch {
			case k == "state":
				d.State = v
			case strings.HasPrefix(k, "total size"), k == "size":
				d.Size = v
			case k == "model":
				d.Model = v
			case strings.HasPrefix(k, "serial"):
				d.Serial = v
			case strings.HasPrefix(k, "reported location"), strings.HasPrefix(k, "reported channel"):
				if v != "" {
					d.Location = v
				}
			}
		}
	}
	flush()
	if len(ctrl.Drives) == 0 {
		return nil
	}
	return ctrl
}

func classifyAACState(d *Drive) {
	s := strings.ToLower(d.State)
	switch {
	case strings.Contains(s, "online"), strings.Contains(s, "ready"), strings.Contains(s, "hot spare"), strings.Contains(s, "optimal"):
		d.Health = "PASSED"
	case strings.Contains(s, "fail"), strings.Contains(s, "missing"), strings.Contains(s, "dead"):
		d.Failed, d.Health, d.Note = true, "FAILED", "controller reports the drive state as "+d.State
	case strings.Contains(s, "rebuild"), strings.Contains(s, "verify"):
		d.Degraded, d.Note = true, "drive is rebuilding / verifying — the array is degraded"
	}
}

// ---- small helpers -------------------------------------------------------

func baseName(p string) string { return filepath.Base(p) }

func mstr(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func mnum(m map[string]any, k string) int {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return int(i)
			}
		case string:
			return atoiDefault(n, -1)
		}
	}
	return -1
}

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	n := 0
	if s == "" {
		return def
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
