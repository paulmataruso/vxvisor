package service

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"vdxclone/internal/platform"
)

// Platform entry points (M8): host passthrough capability and image import.

// HostCapability reports host passthrough (IOMMU/VFIO) readiness.
func (s *Service) HostCapability(p *Principal) platform.Passthrough {
	return platform.DetectPassthrough()
}

// ImportImageURL downloads a foreign VM disk and converts it to a qcow2 base
// image (VMDK/VHD/raw → qcow2 via qemu-img). Instance admins only.
func (s *Service) ImportImageURL(p *Principal, name, url, ip string) (string, error) {
	if !p.atLeast("admin") {
		return "", ErrUnauthorized
	}
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(s.cfg.Paths.ImageDir, "import-*.disk")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	tmp.Close()
	img, err := platform.ImportDisk(s.cfg, s.db, name, tmpPath)
	if err != nil {
		return "", err
	}
	s.audit(p, p.OrgID, "image.import", "image", img, ip, map[string]any{"source": url})
	return img, nil
}
