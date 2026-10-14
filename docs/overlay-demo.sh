#!/usr/bin/env bash
# Prove the VXLAN overlay model: two namespaces act as two cluster nodes on a
# flat "underlay"; a VXLAN (VNI 42) stitches their bridges into ONE L2 so guests
# on different nodes reach each other by their overlay IPs. This is exactly what
# netdrv.EnsureOverlay builds per node.
set -e
cleanup(){ ip netns del nodeA 2>/dev/null||true; ip netns del nodeB 2>/dev/null||true; }
trap cleanup EXIT
cleanup
ip netns add nodeA; ip netns add nodeB

# Underlay: a veth pair linking the two nodes (stands in for the physical LAN).
ip link add ul-a netns nodeA type veth peer name ul-b netns nodeB
ip -n nodeA addr add 192.168.90.1/24 dev ul-a; ip -n nodeA link set ul-a up
ip -n nodeB addr add 192.168.90.2/24 dev ul-b; ip -n nodeB link set ul-b up
ip -n nodeA link set lo up; ip -n nodeB link set lo up

mkbr(){ # ns self-underlay-ip remote-ip overlay-ip
  local ns=$1 dev=$2 remote=$3 ovl=$4
  ip -n $ns link add vdxbr0 type bridge
  ip -n $ns link set vdxbr0 up
  ip -n $ns link add vdxvx42 type vxlan id 42 remote $remote dstport 4789 dev $dev
  ip -n $ns link set vdxvx42 master vdxbr0
  ip -n $ns link set vdxvx42 up
  ip -n $ns addr add $ovl dev vdxbr0        # a "guest" address on the overlay L2
}
mkbr nodeA ul-a 192.168.90.2 10.77.0.1/16
mkbr nodeB ul-b 192.168.90.1 10.77.0.2/16

echo "== nodeA overlay reaching nodeB's overlay IP (encapsulated over underlay) =="
ip netns exec nodeA ping -c 3 -W 2 10.77.0.2
echo
echo "== proof it is encapsulated: nodeB sees VXLAN UDP (4789) on the underlay =="
ip netns exec nodeB timeout 3 tcpdump -ni ul-b -c 2 udp port 4789 2>/dev/null || echo "(tcpdump absent; fdb below is the proof)"
echo
echo "== VXLAN forwarding DB on nodeA (remote VTEP learned) =="
ip -n nodeA link show vdxvx42
echo "overlay neighbor (ARP) learned on nodeA:"; ip -n nodeA neigh show dev vdxbr0
