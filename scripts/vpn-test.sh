#!/usr/bin/env bash
# Peer-to-peer VPN over a straw relay, in Linux network namespaces (P3).
#
#   peerA(pa) ── relay(r) ── peerB(pb)     relay routes the two links + --udp-bind
#
# peerA is the VPN server (assigned the 10.9.0.0/24 gateway .1), peerB the
# client (assigned .2); both run straw's CONNECT-IP stack over the peer
# connection through the relay. The test pings peerA's tunnel address from
# peerB, across the tunnel.
#
#   sudo scripts/vpn-test.sh
#   BDD_KEEP is not honoured; namespaces are torn down on exit.
set -uo pipefail
BIN=${BIN:-target/debug}
OUT=${OUT:-/tmp/strawvpn}
PORT=4433
mkdir -p "$OUT"
log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[32mOK: %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; }
[ "$(id -u)" = 0 ] || { echo "run under sudo"; exit 1; }

NSES="vpn_pa vpn_r vpn_pb"
cleanup() {
    set +e
    pkill -f "$BIN/strawcat" 2>/dev/null
    pkill -f "$BIN/straw " 2>/dev/null
    for ns in $NSES; do ip netns del $ns 2>/dev/null; done
}
trap cleanup EXIT
cleanup

log "topology"
for ns in $NSES; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
link() { # ns1 if1 addr1 ns2 if2 addr2
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"; ip -n "$4" addr add "$6" dev "$5"
    ip -n "$1" link set "$2" up;     ip -n "$4" link set "$5" up
}
link vpn_pa eth0 10.10.0.2/24 vpn_r ra 10.10.0.1/24
link vpn_pb eth0 10.10.1.2/24 vpn_r rb 10.10.1.1/24
ip -n vpn_pa route add default via 10.10.0.1
ip -n vpn_pb route add default via 10.10.1.1
ip netns exec vpn_r sysctl -qw net.ipv4.ip_forward=1 >/dev/null
ip netns exec vpn_pa ping -c1 -W2 10.10.0.1 >/dev/null && ip netns exec vpn_pb ping -c1 -W2 10.10.1.1 >/dev/null \
    && ok "peers reach the relay" || { fail "connectivity"; exit 1; }

log "relay: straw --udp-bind"
ip netns exec vpn_r env RUST_LOG=straw=info "$BIN/straw" \
    --listen 10.10.0.1:$PORT --udp-bind --udp-bind-public-ips 10.10.0.1,10.10.1.1 \
    --udp-bind-port-lo 30000 --udp-bind-port-hi 30999 --udp-bind-allow-dest 10.0.0.0/8 \
    --auth-mode bearer --auth-token s3cret >"$OUT/relay.log" 2>&1 &
for _ in $(seq 100); do grep -q listening "$OUT/relay.log" && break; sleep 0.1; done

"$BIN/strawcat" genkey >"$OUT/a.key" 2>/dev/null
"$BIN/strawcat" genkey >"$OUT/b.key" 2>/dev/null

log "peerA: VPN server (listen)"
ip netns exec vpn_pa env RUST_LOG=straw=info "$BIN/strawcat" listen \
    --relay 10.10.0.1:$PORT --insecure --bearer-token s3cret --identity "$OUT/a.key" \
    --vpn --vpn-subnet 10.9.0.0/24 --vpn-tun sc0 >"$OUT/a.out" 2>"$OUT/a.err" &
for _ in $(seq 100); do [ -s "$OUT/a.out" ] && break; sleep 0.1; done
TOKEN=$(head -1 "$OUT/a.out")
[ -n "$TOKEN" ] && ok "token minted" || { tail -5 "$OUT/a.err"; fail "no token"; exit 1; }

log "peerB: VPN client (connect)"
ip netns exec vpn_pb env RUST_LOG=straw=info "$BIN/strawcat" connect "$TOKEN" \
    --relay 10.10.0.1:$PORT --insecure --bearer-token s3cret --identity "$OUT/b.key" \
    --vpn --vpn-tun sc0 >"$OUT/b.out" 2>"$OUT/b.err" &
# wait for both tunnel devices to come up with an address
for _ in $(seq 120); do
    ip -n vpn_pa addr show sc0 2>/dev/null | grep -q "inet 10.9" \
        && ip -n vpn_pb addr show sc0 2>/dev/null | grep -q "inet 10.9" && break
    sleep 0.25
done

log "tunnel state"
A_ADDR=$(ip -n vpn_pa addr show sc0 2>/dev/null | grep -oE "inet 10.9[0-9./]*" | head -1)
B_ADDR=$(ip -n vpn_pb addr show sc0 2>/dev/null | grep -oE "inet 10.9[0-9./]*" | head -1)
echo "  peerA sc0: ${A_ADDR:-<none>}"
echo "  peerB sc0: ${B_ADDR:-<none>}"
[ -n "$A_ADDR" ] && [ -n "$B_ADDR" ] || { fail "tunnel addresses not assigned"; tail -8 "$OUT/a.err" "$OUT/b.err"; exit 1; }

log "path in use"
# No NAT between these peers, so the native punch must reach a direct path —
# and this is the case that proves the Stage 3 candidate exchange is at the
# QUIC layer: the inner protocol here is h3, which an app-level exchange
# stream would have collided with. The address named must be the *peer's*
# (10.10.0.2 / 10.10.1.2), never the relay's 10.10.x.1.
A_PATH=$(grep -oE 'path: .*' "$OUT/a.err" | head -1)
B_PATH=$(grep -oE 'path: .*' "$OUT/b.err" | head -1)
echo "  peerA $A_PATH"
echo "  peerB $B_PATH"
if echo "$A_PATH" | grep -q "peer 10.10.1.2:" && echo "$B_PATH" | grep -q "peer 10.10.0.2:"; then
    ok "VPN runs over a direct path to the peer, bypassing the relay"
else
    fail "VPN did not reach a direct path to the peer (h3 over native NAT traversal)"
    exit 1
fi

log "ping across the tunnel (peerB → peerA's 10.9.0.1)"
if ip netns exec vpn_pb ping -c3 -W2 10.9.0.1 >"$OUT/ping.out" 2>&1; then
    ok "peerB reached peerA's tunnel address across the VPN"
    grep -oE "[0-9]+ received" "$OUT/ping.out" | sed 's/^/  /'
else
    fail "ping across the VPN failed"
    echo "--- peerA err ---"; tail -10 "$OUT/a.err"
    echo "--- peerB err ---"; tail -10 "$OUT/b.err"
    echo "--- ping ---"; tail -4 "$OUT/ping.out"
    exit 1
fi
