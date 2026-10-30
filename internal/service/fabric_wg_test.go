package service

import (
	"strings"
	"testing"

	"vdxclone/internal/fabric"
)

// A fabric's underlay is fixed once it exists: every member vetoes a change.
func TestFabricCheckUnderlayFixed(t *testing.T) {
	s := &Service{}
	k1, _ := fabric.NewWGKey()
	pub, _ := fabric.WGPublic(k1)
	cur := fabric.Intent{Fabrics: []fabric.Spec{{UUID: "11111111-1111-4111-8111-111111111111", Name: "f", ASN: 65100, MTU: 1440,
		Underlay: fabric.UnderlayMgmt, Hosts: []fabric.Host{{Node: "elsewhere", Iface: "vSwitch0", TEP: "10.250.0.1/24", Endpoint: "172.16.0.11", WGPub: pub}}}}}
	next := cur.Clone()
	next.Fabrics[0].Underlay = ""
	if err := s.fabricCheck(cur, next); err == nil || !strings.Contains(err.Error(), "can't change") {
		t.Fatalf("underlay change: %v", err)
	}
}

func TestFabricWGPeerStale(t *testing.T) {
	if !(FabricWGPeer{}).Stale() || (FabricWGPeer{}).HandshakeAge() != "never" {
		t.Fatalf("no handshake must read as stale / never")
	}
}
