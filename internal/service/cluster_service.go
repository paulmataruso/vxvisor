package service

import (
	"errors"
	"fmt"

	"vdxclone/internal/cluster"
)

// Cluster entry points (M7). Node administration is instance-admin only.

func (s *Service) ListNodes(p *Principal) ([]cluster.Node, error) {
	if !p.atLeast("member") || s.cl == nil {
		return nil, nil
	}
	return s.cl.ListNodes()
}

func (s *Service) AddNode(p *Principal, name, address, sshUser, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	id, err := s.cl.AddNode(name, address, sshUser)
	if err != nil {
		return err
	}
	s.audit(p, p.OrgID, "node.add", "node", fmt.Sprint(id), ip, map[string]any{"name": name, "address": address})
	return nil
}

func (s *Service) DeleteNode(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	if err := s.cl.DeleteNode(id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "node.delete", "node", fmt.Sprint(id), ip, nil)
	return nil
}

func (s *Service) ProbeNode(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	n, err := s.cl.GetNode(id)
	if err != nil {
		return ErrNotFound
	}
	s.cl.Probe(n)
	return nil
}

// MigrateSession performs a live migration of a running VM to another node over
// the cluster overlay. It builds the receiver spec, derives the incoming port,
// and hands off to the cluster orchestrator, which runs the real QMP migration
// when the preconditions hold (two nodes + shared storage, or block migration)
// and otherwise refuses with a clear reason rather than corrupting the guest.
func (s *Service) MigrateSession(p *Principal, sessionID string, dstNodeID int64, sharedStorage bool, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return err
	}
	if !s.mgr.Running(sess) {
		return errors.New("instance is not running")
	}
	nodes, _ := s.cl.ListNodes()
	var src, dst cluster.Node
	for _, n := range nodes {
		if n.Role == "local" {
			src = n
		}
		if n.ID == dstNodeID {
			dst = n
		}
	}
	spec, err := s.mgr.ReceiverSpec(sessionID)
	if err != nil {
		return err
	}
	// Shared storage from the explicit flag OR a configured cluster mount.
	shared := sharedStorage || s.cfg.Cluster.SharedStorage != ""
	port := s.cfg.Cluster.MigratePort
	if port == 0 {
		port = 49200
	}
	err = s.cl.Migrate(cluster.MigrateReq{
		Src: src, Dst: dst,
		SessionID:     sessionID,
		LocalQMP:      sess.QMPSocket,
		IncomingPort:  port,
		SharedStorage: shared,
		BlockMigrate:  !shared, // no shared storage → copy the disk inline
		ReceiverSpec:  spec,
	})
	s.audit(p, p.OrgID, "session.migrate", "session", sessionID, ip, map[string]any{"dst_node": dstNodeID, "ok": err == nil})
	return err
}
