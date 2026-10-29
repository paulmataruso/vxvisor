package ceph

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RBD snapshots and instant clones of the images that back VM disks
// (docs/SNAPSHOTS.md). Every call names one pool/image[@snap] explicitly; nothing
// here purges or recurses. A clone is a copy-on-write child of a PROTECTED
// snapshot, so the snapshot can't be removed while children exist (rbd refuses
// to unprotect it); Flatten copies the parent's data into the child to end the
// dependency.

// runCmd is the command runner the snapshot calls use (a var so tests can record
// the exact argv without a Ceph cluster).
var runCmd = run

func validRBDName(kind, s string) error {
	if s == "" {
		return fmt.Errorf("rbd %s name required", kind)
	}
	// A leading letter/digit: never read as an option, never "." / "..".
	if c := s[0]; !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
		return fmt.Errorf("invalid rbd %s name %q", kind, s)
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid rbd %s name %q", kind, s)
		}
	}
	return nil
}

func imageSpec(pool, image string) (string, error) {
	if err := validRBDName("pool", pool); err != nil {
		return "", err
	}
	if err := validRBDName("image", image); err != nil {
		return "", err
	}
	return pool + "/" + image, nil
}

func snapSpec(pool, image, tag string) (string, error) {
	img, err := imageSpec(pool, image)
	if err != nil {
		return "", err
	}
	if err := validRBDName("snapshot", tag); err != nil {
		return "", err
	}
	return img + "@" + tag, nil
}

// SnapCreate takes a crash-consistent point-in-time snapshot of pool/image. Safe
// while a running VM has the image open (librbd's exclusive lock owner performs it).
func SnapCreate(pool, image, tag string) error {
	sn, err := snapSpec(pool, image, tag)
	if err != nil {
		return err
	}
	_, err = runCmd(60*time.Second, "rbd", "snap", "create", sn)
	return err
}

// SnapRollback rewrites pool/image with the snapshot's contents. The image must
// not be open (the VM is stopped). Other snapshots are untouched.
func SnapRollback(pool, image, tag string) error {
	sn, err := snapSpec(pool, image, tag)
	if err != nil {
		return err
	}
	_, err = runCmd(30*time.Minute, "rbd", "snap", "rollback", "--no-progress", sn)
	return err
}

// SnapRemove removes pool/image@tag, unprotecting it first if a clone ever
// protected it. Unprotect fails while children exist, so a snapshot an instant
// clone still depends on can never be removed through here.
func SnapRemove(pool, image, tag string) error {
	sn, err := snapSpec(pool, image, tag)
	if err != nil {
		return err
	}
	if _, err := runCmd(60*time.Second, "rbd", "snap", "unprotect", sn); err != nil && !notProtected(err) {
		return err
	}
	_, err = runCmd(60*time.Second, "rbd", "snap", "rm", "--no-progress", sn)
	return err
}

// Clone protects pool/image@tag (idempotent) and creates pool/dst as its
// copy-on-write child — instant, sharing every unchanged block with the parent.
func Clone(pool, image, tag, dst string) error {
	sn, err := snapSpec(pool, image, tag)
	if err != nil {
		return err
	}
	child, err := imageSpec(pool, dst)
	if err != nil {
		return err
	}
	if _, err := runCmd(60*time.Second, "rbd", "snap", "protect", sn); err != nil && !alreadyProtected(err) {
		return err
	}
	_, err = runCmd(120*time.Second, "rbd", "clone", sn, child)
	return err
}

// Flatten copies every block a child still reads from its parent snapshot into
// the child, making it independent. Proportional to the image size.
func Flatten(pool, image string) error {
	img, err := imageSpec(pool, image)
	if err != nil {
		return err
	}
	_, err = runCmd(6*time.Hour, "rbd", "flatten", "--no-progress", img)
	return err
}

// Children lists the clones (pool/image) of pool/image@tag.
func Children(pool, image, tag string) ([]string, error) {
	sn, err := snapSpec(pool, image, tag)
	if err != nil {
		return nil, err
	}
	out, err := runCmd(30*time.Second, "rbd", "children", "--format", "json", sn)
	if err != nil {
		return nil, err
	}
	var kids []struct {
		Pool  string `json:"pool"`
		Image string `json:"image"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &kids); err != nil {
		return nil, fmt.Errorf("parse rbd children: %w", err)
	}
	var names []string
	for _, k := range kids {
		names = append(names, k.Pool+"/"+k.Image)
	}
	return names, nil
}

// notProtected matches rbd's refusal to unprotect a snapshot that isn't
// protected ("snapshot is already unprotected"), which SnapRemove treats as done.
func notProtected(err error) bool {
	m := err.Error()
	return strings.Contains(m, "already unprotected") || strings.Contains(m, "not protected")
}

func alreadyProtected(err error) bool {
	return strings.Contains(err.Error(), "already protected")
}
