// Package platform implements the operator-facing platform features: in-place
// self-update from an operator-controlled feed, importing foreign VM disks
// (VMDK/VHD/raw → qcow2), and detecting host passthrough (IOMMU/VFIO) capability.
//
// None of this contacts a vendor. The self-update feed URL is configured by the
// operator and points wherever they choose.
package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"vdxclone/internal/config"
	"vdxclone/internal/db"
)

// ---- self-update ---------------------------------------------------------

// Release is one entry in the update feed manifest.
type Release struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// CheckUpdate fetches the feed and returns the advertised release.
func CheckUpdate(feedURL string) (Release, error) {
	if feedURL == "" {
		return Release{}, fmt.Errorf("no update feed configured ([update] feed_url)")
	}
	resp, err := http.Get(feedURL)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("update feed: HTTP %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, err
	}
	if rel.Version == "" || rel.URL == "" {
		return Release{}, fmt.Errorf("update feed missing version/url")
	}
	return rel, nil
}

// ApplyUpdate downloads a release, verifies its SHA-256, and atomically swaps the
// running binary (keeping a .bak). The caller then restarts the service.
func ApplyUpdate(rel Release, binPath string) error {
	resp, err := http.Get(rel.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", rel.URL, resp.StatusCode)
	}
	tmp := binPath + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	got := hex.EncodeToString(h.Sum(nil))
	if rel.SHA256 != "" && !strings.EqualFold(got, rel.SHA256) {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch: feed=%s got=%s", rel.SHA256, got)
	}
	// Swap: current → .bak, new → current. Rename within a dir is atomic.
	_ = os.Rename(binPath, binPath+".bak")
	if err := os.Rename(tmp, binPath); err != nil {
		_ = os.Rename(binPath+".bak", binPath) // roll back
		return err
	}
	return nil
}

// ---- import --------------------------------------------------------------

// ImportDisk converts a foreign VM disk (VMDK/VHD/VPC/raw — anything qemu-img
// reads) into a qcow2 base image and registers it. ESXi OVA/OVF should first be
// unpacked (tar) to its .vmdk; Proxmox vma streams convert similarly.
func ImportDisk(cfg *config.Config, d *db.DB, name, srcPath string) (string, error) {
	if _, err := os.Stat(srcPath); err != nil {
		return "", fmt.Errorf("source not found: %s", srcPath)
	}
	imgName := safe(name)
	dest := filepath.Join(cfg.Paths.ImageDir, imgName+".qcow2")
	cmd := exec.Command("qemu-img", "convert", "-O", "qcow2", srcPath, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("qemu-img convert: %v: %s", err, out)
	}
	var size int64
	if fi, err := os.Stat(dest); err == nil {
		size = fi.Size()
	}
	if _, err := d.Exec(`INSERT INTO images(name,path,source_url,size_bytes,status) VALUES(?,?,?,?,'ready')
		ON CONFLICT(name) DO UPDATE SET path=excluded.path, size_bytes=excluded.size_bytes, status='ready'`,
		imgName, dest, "import:"+filepath.Base(srcPath), size); err != nil {
		os.Remove(dest)
		return "", err
	}
	return imgName, nil
}

// ---- passthrough capability ----------------------------------------------

// Passthrough reports host device-passthrough readiness.
type Passthrough struct {
	IOMMU       bool   `json:"iommu"`
	VFIO        bool   `json:"vfio"`
	IOMMUGroups int    `json:"iommu_groups"`
	Note        string `json:"note"`
}

// DetectPassthrough inspects the host for IOMMU + VFIO. GPU/USB passthrough
// cannot be enabled without these (and usually a BIOS change + reboot), so this
// pre-flight lets the UI explain what is missing instead of failing a VM start.
func DetectPassthrough() Passthrough {
	var p Passthrough
	if entries, err := os.ReadDir("/sys/kernel/iommu_groups"); err == nil {
		p.IOMMUGroups = len(entries)
		p.IOMMU = len(entries) > 0
	}
	if _, err := os.Stat("/sys/module/vfio_pci"); err == nil {
		p.VFIO = true
	} else if _, err := os.Stat("/dev/vfio/vfio"); err == nil {
		p.VFIO = true
	}
	switch {
	case p.IOMMU && p.VFIO:
		p.Note = "ready for PCI/USB passthrough"
	case !p.IOMMU:
		p.Note = "IOMMU not enabled — set intel_iommu=on/amd_iommu=on in the kernel cmdline and reboot"
	default:
		p.Note = "load the vfio-pci module to enable passthrough"
	}
	return p
}

func safe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "import"
	}
	return string(out)
}
