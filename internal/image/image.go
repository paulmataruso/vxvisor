// Package image manages base VM images (qcow2 cloud images).
package image

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"vdxclone/internal/config"
	"vdxclone/internal/db"
)

// Catalog maps short names to upstream Ubuntu cloud image URLs. These are
// public, freely redistributable images — not part of any proprietary product.
var Catalog = map[string]string{
	"ubuntu-24.04": "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
	"ubuntu-22.04": "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img",
}

// Pull downloads a catalog image into the image cache and records it, unless it
// already exists. It streams to a .part file and renames on success.
func Pull(cfg *config.Config, d *db.DB, name string) error {
	url, ok := Catalog[name]
	if !ok {
		return fmt.Errorf("unknown image %q", name)
	}
	dest := filepath.Join(cfg.Paths.ImageDir, name+".qcow2")
	if _, err := os.Stat(dest); err == nil {
		return record(d, name, dest, url)
	}

	_, _ = d.Exec(`INSERT INTO images(name,path,source_url,status) VALUES(?,?,?,'downloading')
		ON CONFLICT(name) DO UPDATE SET status='downloading'`, name, dest, url)

	resp, err := http.Get(url)
	if err != nil {
		_, _ = d.Exec(`UPDATE images SET status='error' WHERE name=?`, name)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = d.Exec(`UPDATE images SET status='error' WHERE name=?`, name)
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		_, _ = d.Exec(`UPDATE images SET status='error' WHERE name=?`, name)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	_, _ = d.Exec(`UPDATE images SET path=?, size_bytes=?, status='ready' WHERE name=?`, dest, n, name)
	return nil
}

func record(d *db.DB, name, path, url string) error {
	fi, _ := os.Stat(path)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	_, err := d.Exec(`INSERT INTO images(name,path,source_url,size_bytes,status) VALUES(?,?,?,?,'ready')
		ON CONFLICT(name) DO UPDATE SET path=excluded.path, size_bytes=excluded.size_bytes, status='ready'`,
		name, path, url, size)
	return err
}

type Image struct {
	Name       string
	Status     string
	SizeBytes  int64
}

func List(d *db.DB) ([]Image, error) {
	rows, err := d.Query(`SELECT name, status, size_bytes FROM images ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Image
	for rows.Next() {
		var im Image
		if err := rows.Scan(&im.Name, &im.Status, &im.SizeBytes); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}
