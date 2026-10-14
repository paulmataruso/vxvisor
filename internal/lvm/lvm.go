// Package lvm wraps the LVM2 CLIs to manage thin pools (and the thin volumes
// used as VM disks) from the UI. It also exposes RemoveVG so the UI can free a
// disk (e.g. the pre-existing "vmstore" VG) before repurposing it for ZFS.
// Shells out to pvcreate/vgcreate/lvcreate/vgremove; admin-gated by the caller.
package lvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Available reports whether the LVM2 tools are installed.
func Available() bool {
	_, err := exec.LookPath("lvs")
	return err == nil
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ThinPool is an LVM thin pool as the UI shows it.
type ThinPool struct {
	VG         string  `json:"vg"`
	Name       string  `json:"name"`        // thin-pool LV name
	SizeBytes  int64   `json:"size_bytes"`
	DataPct    float64 `json:"data_pct"`    // % of the pool allocated
	MetaPct    float64 `json:"meta_pct"`    // % of metadata used
}

type lvsReport struct {
	Report []struct {
		LV []struct {
			LVName       string `json:"lv_name"`
			VGName       string `json:"vg_name"`
			LVSize       string `json:"lv_size"`
			LVAttr       string `json:"lv_attr"`
			DataPercent  string `json:"data_percent"`
			MetaPercent  string `json:"metadata_percent"`
		} `json:"lv"`
	} `json:"report"`
}

// ListThinPools returns every LVM thin pool on the host.
func ListThinPools() ([]ThinPool, error) {
	if !Available() {
		return nil, nil
	}
	out, err := run(10*time.Second, "lvs", "--reportformat", "json", "--units", "b", "--nosuffix",
		"-o", "lv_name,vg_name,lv_size,lv_attr,data_percent,metadata_percent")
	if err != nil {
		return nil, err
	}
	var rep lvsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		return nil, err
	}
	var pools []ThinPool
	for _, r := range rep.Report {
		for _, lv := range r.LV {
			// Thin pools have 't' as the first attr char.
			if len(lv.LVAttr) == 0 || lv.LVAttr[0] != 't' {
				continue
			}
			pools = append(pools, ThinPool{
				VG: lv.VGName, Name: lv.LVName,
				SizeBytes: atoi64(lv.LVSize),
				DataPct:   atof(lv.DataPercent), MetaPct: atof(lv.MetaPercent),
			})
		}
	}
	return pools, nil
}

// CreateThinPool wipes `devices`, makes them PVs, creates volume group `vg`, and
// a thin pool LV `pool` spanning its free space. Destructive; caller confirms.
func CreateThinPool(vg, pool string, devices []string) error {
	if err := validName(vg); err != nil {
		return err
	}
	if err := validName(pool); err != nil {
		return err
	}
	if len(devices) == 0 {
		return errors.New("no devices selected")
	}
	for _, d := range devices {
		if d == "" {
			return errors.New("empty device path")
		}
		if _, err := run(30*time.Second, "pvcreate", "-f", d); err != nil {
			return err
		}
	}
	vgArgs := append([]string{vg}, devices...)
	if _, err := run(30*time.Second, "vgcreate", vgArgs...); err != nil {
		return err
	}
	// Thin pool over all free extents of the VG.
	_, err := run(30*time.Second, "lvcreate", "--type", "thin-pool", "-l", "100%FREE", "-n", pool, vg)
	return err
}

// CreateThinVolume creates a thin LV of sizeBytes in vg/pool, usable as a raw VM
// disk at /dev/<vg>/<name>.
func CreateThinVolume(vg, pool, name string, sizeBytes int64) error {
	for _, n := range []string{vg, pool, name} {
		if err := validName(n); err != nil {
			return err
		}
	}
	if sizeBytes <= 0 {
		return errors.New("volume size must be positive")
	}
	_, err := run(30*time.Second, "lvcreate", "--type", "thin",
		"-V", strconv.FormatInt(sizeBytes, 10)+"b", "--thinpool", pool, "-n", name, vg)
	return err
}

// RemoveVG removes a volume group and clears its PVs, freeing the underlying
// disks (used to repurpose e.g. "vmstore" for ZFS). Destructive; caller confirms.
func RemoveVG(vg string) error {
	if err := validName(vg); err != nil {
		return err
	}
	// Find PVs backing the VG before we drop it, so we can wipe them after.
	pvs, _ := pvsForVG(vg)
	if _, err := run(300*time.Second, "vgremove", "-f", vg); err != nil {
		return err
	}
	for _, pv := range pvs {
		_, _ = run(30*time.Second, "pvremove", "-ff", "-y", pv)
		// Clear ALL residual signatures (LVM label + any stale partition table)
		// so the disk reads as truly free, not just LVM-free.
		_, _ = run(30*time.Second, "wipefs", "-a", pv)
	}
	// Let udev tear down the device-mapper nodes before we return, so the next
	// listing reflects reality (no stale "in use" from half-removed dm devices).
	_, _ = run(30*time.Second, "udevadm", "settle")
	return nil
}

func pvsForVG(vg string) ([]string, error) {
	out, err := run(10*time.Second, "pvs", "--reportformat", "json", "-o", "pv_name,vg_name")
	if err != nil {
		return nil, err
	}
	var rep struct {
		Report []struct {
			PV []struct {
				PVName string `json:"pv_name"`
				VGName string `json:"vg_name"`
			} `json:"pv"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		return nil, err
	}
	var pvs []string
	for _, r := range rep.Report {
		for _, pv := range r.PV {
			if pv.VGName == vg {
				pvs = append(pvs, pv.PVName)
			}
		}
	}
	return pvs, nil
}

func validName(name string) error {
	if name == "" {
		return errors.New("name required")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid name %q", name)
		}
	}
	return nil
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
