#!/usr/bin/env bash
# Real-NAT hole-punch test for the P2P direct path.
#
# Topology — two peers behind separate Linux MASQUERADE NATs, joined by a
# relay that also routes between the two "public" links (no bridge):
#
#   peerA(pa) ─ natA(na) ══ relay(r) ══ natB(nb) ─ peerB(pb)
#   10.1.0.2   10.1.0.1     .1  .5     10.2.0.1   10.2.0.2
#              192.0.2.2   192.0.2.x   192.0.2.6
#
#   relay: 192.0.2.1/30 (link A) + 192.0.2.5/30 (link B), ip_forward=1
#
# Checks the relay path works through real NAT, then whether the peers
# hole-punch a direct path — the honest question this harness answers.
#
#   sudo scripts/nat-punch-test.sh
set -uo pipefail
BIN=${BIN:-target/debug}
PORT=4433
OUT=${OUT:-/tmp/natpunch}
mkdir -p "$OUT"
log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[32mOK: %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; }
[ "$(id -u)" = 0 ] || { echo "run under sudo"; exit 1; }

NSES="natpunch_pa natpunch_na natpunch_r natpunch_nb natpunch_pb"
cleanup() {
    set +e
    pkill -f "$BIN/strawcat" 2>/dev/null; pkill -f "$BIN/straw " 2>/dev/null
    for ns in $NSES; do ip netns del $ns 2>/dev/null; done
    set -e
}
trap cleanup EXIT
cleanup 2>/dev/null

link() { # nsA ifA cidrA nsB ifB cidrB
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ip -n "$1" addr add "$3" dev "$2"; ip -n "$1" link set "$2" up
    ip -n "$4" addr add "$6" dev "$5"; ip -n "$4" link set "$5" up
}

log "topology"
for ns in $NSES; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
# peer ─ nat (internal)
link natpunch_pa inside 10.1.0.2/24 natpunch_na internal 10.1.0.1/24
link natpunch_pb inside 10.2.0.2/24 natpunch_nb internal 10.2.0.1/24
# nat ─ relay (public, point-to-point /30)
link natpunch_na public 192.0.2.2/30 natpunch_r pubA 192.0.2.1/30
link natpunch_nb public 192.0.2.6/30 natpunch_r pubB 192.0.2.5/30
# routes: peers default via their nat; nats default via the relay.
ip -n natpunch_pa route add default via 10.1.0.1
ip -n natpunch_pb route add default via 10.2.0.1
ip -n natpunch_na route add default via 192.0.2.1
ip -n natpunch_nb route add default via 192.0.2.5
# the relay routes between the two public links.
ip netns exec natpunch_r sysctl -qw net.ipv4.ip_forward=1 \
    net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
# NAT: MASQUERADE each internal subnet out the nat's public interface.
for pair in "natpunch_na 10.1.0.0/24" "natpunch_nb 10.2.0.0/24"; do
    set -- $pair
    ip netns exec $1 sysctl -qw net.ipv4.ip_forward=1 \
        net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
    ip netns exec $1 iptables -P FORWARD ACCEPT
    ip netns exec $1 iptables -t nat -A POSTROUTING -s $2 -o public -j MASQUERADE
done

log "sanity"
ip netns exec natpunch_pa ping -c1 -W2 192.0.2.1 >/dev/null && echo "  peerA → relay OK" || fail "peerA → relay"
ip netns exec natpunch_pb ping -c1 -W2 192.0.2.1 >/dev/null && echo "  peerB → relay OK" || fail "peerB → relay"
if ip netns exec natpunch_pa ping -c1 -W1 10.2.0.2 >/dev/null 2>&1; then
    fail "peerA reached peerB's private addr — not NATed"
else echo "  peerA ✗ peerB private (correct — separated by NAT)"; fi

log "relay: straw --udp-bind"
ip netns exec natpunch_r env RUST_LOG=straw=info "$BIN/straw" \
    --listen 192.0.2.1:$PORT --udp-bind --udp-bind-public-ips 192.0.2.1 \
    --udp-bind-port-lo 30000 --udp-bind-port-hi 30999 --udp-bind-allow-dest 192.0.2.0/24 \
    --auth-mode bearer --auth-token s3cret >"$OUT/np_relay.log" 2>&1 &
for _ in $(seq 100); do grep -q listening "$OUT/np_relay.log" && break; sleep 0.1; done
grep -q listening "$OUT/np_relay.log" || { cat "$OUT/np_relay.log"; fail "relay start"; exit 1; }

"$BIN/strawcat" genkey >"$OUT/np_a.key" 2>/dev/null
"$BIN/strawcat" genkey >"$OUT/np_b.key" 2>/dev/null

# Bounded so a stalled pipe can never hang the harness: each peer sends its
# line, holds the pipe open briefly, then the whole strawcat is force-timed-out.
PUNCH_WAIT=${PUNCH_WAIT:-6}
HOLD=${HOLD:-3}
PEER_TL=$((PUNCH_WAIT + HOLD + 6))

log "peerA listens (issuer)"
( printf 'HELLO-FROM-A\n'; sleep "$HOLD" ) | ip netns exec natpunch_pa env RUST_LOG=straw=debug \
    timeout -s INT "$PEER_TL" \
    "$BIN/strawcat" listen --relay 192.0.2.1:$PORT --insecure --bearer-token s3cret \
    --identity "$OUT/np_a.key" --punch-wait "$PUNCH_WAIT" \
    >"$OUT/np_listen.out" 2>"$OUT/np_listen.err" &
LISTEN_PID=$!
for _ in $(seq 100); do [ -s "$OUT/np_listen.out" ] && break; sleep 0.1; done
TOKEN=$(head -1 "$OUT/np_listen.out")
[ -n "$TOKEN" ] && echo "  token minted" || { tail -5 "$OUT/np_listen.err"; fail "no token"; exit 1; }

log "peerB connects (holder)"
( printf 'HELLO-FROM-B\n'; sleep "$HOLD" ) | ip netns exec natpunch_pb env RUST_LOG=straw=debug \
    timeout -s INT "$PEER_TL" \
    "$BIN/strawcat" connect "$TOKEN" --relay 192.0.2.1:$PORT --insecure --bearer-token s3cret \
    --identity "$OUT/np_b.key" --punch-wait "$PUNCH_WAIT" \
    >"$OUT/np_connect.out" 2>"$OUT/np_connect.err" || true
wait "$LISTEN_PID" 2>/dev/null || true
sleep 1

log "results"
B_RX=$(tr -d '\0' <"$OUT/np_connect.out")
A_RX=$(tail -n +2 "$OUT/np_listen.out" | tr -d '\0')
A_PATH=$(grep -oE 'path: .*' "$OUT/np_listen.err" | head -1)
B_PATH=$(grep -oE 'path: .*' "$OUT/np_connect.err" | head -1)
echo "  peerB received: '$B_RX'  (expect HELLO-FROM-A)"
echo "  peerA received: '$A_RX'  (expect HELLO-FROM-B)"
echo "  peerA $A_PATH"
echo "  peerB $B_PATH"

# --- Hard assertion: the relay data plane must carry payload both ways
# through the double NAT. This is what the harness proves; the direct-path
# punch is best-effort and NAT-dependent (reported below, never asserted).
DATA_OK=1
[ "$B_RX" = "HELLO-FROM-A" ] || { fail "peerB did not receive peerA's payload over the relay"; DATA_OK=0; }
[ "$A_RX" = "HELLO-FROM-B" ] || { fail "peerA did not receive peerB's payload over the relay"; DATA_OK=0; }
[ "$DATA_OK" = 1 ] && ok "relay data plane carries payload both ways through double NAT"

# --- Informational: did a direct path form? The punch reuses the outer bind
# socket, so on an endpoint-independent (cone) NAT its source matches the
# relay-observed reflexive and the simultaneous open succeeds. This netns
# MASQUERADE is endpoint-DEPENDENT on the holder's side (it maps the same
# socket to a different external port per destination — symmetric behaviour),
# so the punch is blocked and both peers stay on the relay. Either way the
# relay path above must work.
echo
log "hole-punch outcome (best-effort, NAT-dependent)"
if echo "$B_PATH$A_PATH" | grep -q "hole punched"; then
    ok "direct path established — NAT allowed the punch"
else
    echo "  no direct path — both peers stayed on the relay (NAT blocked the punch)"
    echo "  holder punch trace:"
    grep -iE "punch: (local|remote|dialing)|hole punch (failed|timed out)" "$OUT/np_connect.err"         | sed -E 's/\x1b\[[0-9;]*m//g; s/^[0-9T:.-]+Z +[A-Z]+ +[a-z_:]+: //' | head -4 | sed 's/^/    /'
fi

[ "$DATA_OK" = 1 ] || exit 1
