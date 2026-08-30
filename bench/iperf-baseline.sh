#!/usr/bin/env bash
# iperf3 throughput baseline for straw (Phase D).
#
# Topology (network namespaces joined by veth pairs):
#
#   client ──veth── proxy ──veth── origin
#   172.31.0.2    172.31.0.1      10.99.0.2
#                 10.99.0.1 (SNAT out veth1)
#
# Measures, using the release binaries:
#   1. raw veth ceiling  — iperf3 client<->proxy over the bare veth (the
#      netns/CPU limit, no straw in the path)
#   2. tunnel throughput — iperf3 client<->origin through strawc → straw →
#      NAT → origin, i.e. every byte crosses the CONNECT-IP data plane
# each direction (uplink = client sends; downlink = -R), TCP, plus one UDP
# run for datagram loss.
#
#   sudo bench/iperf-baseline.sh [duration_seconds]
#
# Prints a summary table and writes per-run JSON under bench/results/.
set -euo pipefail

DUR=${1:-10}
NS_C=strawbench_client
NS_P=strawbench_proxy
NS_O=strawbench_origin
BIN=${BIN:-target/release}
OUT=bench/results
mkdir -p "$OUT"

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run under sudo (needs netns + TUN)"
[ -x "$BIN/straw" ] && [ -x "$BIN/strawc" ] || fail "build first: cargo build --release --bins"
command -v iperf3 >/dev/null || fail "iperf3 not found"
command -v jq >/dev/null || fail "jq not found"

STRAWC_PID=; STRAW_PID=; IPERF_O_PID=; IPERF_P_PID=
cleanup() {
    set +e
    for p in $STRAWC_PID $STRAW_PID $IPERF_O_PID $IPERF_P_PID; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    for _ in $(seq 20); do ip netns pids $NS_C 2>/dev/null | grep -q . || break; sleep 0.1; done
    for ns in $NS_C $NS_P $NS_O; do ip netns del $ns 2>/dev/null; done
    set -e
}
trap cleanup EXIT
cleanup 2>/dev/null || true

# Create a veth pair with each end renamed into its namespace.
pair() { # ns_a name_a ns_b name_b
    local a="tmp_a$$" b="tmp_b$$"
    ip link add "$a" type veth peer name "$b"
    ip link set "$a" netns "$1" name "$2"
    ip link set "$b" netns "$3" name "$4"
    ip netns exec "$1" ip link set "$2" up
    ip netns exec "$3" ip link set "$4" up
}

log "topology"
for ns in $NS_C $NS_P $NS_O; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
pair $NS_C veth0 $NS_P veth0     # client <-> proxy
pair $NS_P veth1 $NS_O veth0     # proxy  <-> origin
ip netns exec $NS_C ip addr add 172.31.0.2/24 dev veth0
ip netns exec $NS_P ip addr add 172.31.0.1/24 dev veth0
ip netns exec $NS_P ip addr add 10.99.0.1/24 dev veth1
ip netns exec $NS_O ip addr add 10.99.0.2/24 dev veth0
ip netns exec $NS_O ip route add default via 10.99.0.1

log "proxy (straw --tun --nat-interface veth1)"
ip netns exec $NS_P env RUST_LOG=straw=info "$BIN/straw" \
    --listen 0.0.0.0:4433 --tun --nat-interface veth1 >"$OUT/straw.log" 2>&1 &
STRAW_PID=$!
for _ in $(seq 100); do grep -q "proxy listening" "$OUT/straw.log" && break; sleep 0.1; done
grep -q "proxy listening" "$OUT/straw.log" || { cat "$OUT/straw.log"; fail "straw did not start"; }

log "client (strawc)"
ip netns exec $NS_C env RUST_LOG=straw=info "$BIN/strawc" \
    --server-addr 172.31.0.1:4433 --insecure >"$OUT/strawc.log" 2>&1 &
STRAWC_PID=$!
for _ in $(seq 100); do ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 || { cat "$OUT/strawc.log"; fail "strawc0 never appeared"; }
# Let path-MTU discovery ramp so the tunnel runs at full width.
sleep 3
CLIENT_TUN_MTU=$(ip netns exec $NS_C cat /sys/class/net/strawc0/mtu)

# Run one iperf3 case: label server_ns server_ip client_ns extra_flags
run() {
    local label=$1 sns=$2 sip=$3 cns=$4; shift 4
    ip netns exec "$sns" iperf3 -s -1 -B "$sip" >/dev/null 2>&1 &
    local spid=$!
    sleep 0.3
    local json="$OUT/${label}.json"
    if ip netns exec "$cns" iperf3 -c "$sip" -t "$DUR" -J "$@" >"$json" 2>"$OUT/${label}.err"; then
        :
    else
        echo "  ($label failed: $(head -1 "$OUT/${label}.err"))"
    fi
    kill "$spid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
}

fmt_tcp() { # json -> Gbit/s from the receiver's view
    jq -r 'if .end.sum_received then (.end.sum_received.bits_per_second/1e9) else 0 end
           | "\(.*100|round/100) Gbit/s"' "$1" 2>/dev/null || echo "n/a"
}
fmt_udp() { # json -> rate + loss
    jq -r '"\(.end.sum.bits_per_second/1e9*100|round/100) Gbit/s, loss \(.end.sum.lost_percent*100|round/100)%"' "$1" 2>/dev/null || echo "n/a"
}

log "TCP: raw veth ceiling (client <-> proxy, no straw)"
run veth_up   $NS_P 172.31.0.1 $NS_C
run veth_down $NS_P 172.31.0.1 $NS_C -R

log "TCP: through the tunnel (client <-> origin via strawc/straw/NAT)"
run tun_up    $NS_O 10.99.0.2 $NS_C
run tun_down  $NS_O 10.99.0.2 $NS_C -R

log "TCP: through the tunnel, 4 parallel streams (one QUIC connection)"
run tun_up4   $NS_O 10.99.0.2 $NS_C -P 4
run tun_down4 $NS_O 10.99.0.2 $NS_C -R -P 4

log "UDP: through the tunnel, loss-knee sweep"
for rate in 1G 2G 4G 8G; do
    run "tun_udp_$rate" $NS_O 10.99.0.2 $NS_C -u -b "$rate"
done

log "results ($DUR s each; client tunnel MTU $CLIENT_TUN_MTU)"
printf '  %-28s %s\n' "raw veth  uplink:"        "$(fmt_tcp "$OUT/veth_up.json")"
printf '  %-28s %s\n' "raw veth  downlink (-R):" "$(fmt_tcp "$OUT/veth_down.json")"
printf '  %-28s %s\n' "tunnel    uplink:"        "$(fmt_tcp "$OUT/tun_up.json")"
printf '  %-28s %s\n' "tunnel    downlink (-R):" "$(fmt_tcp "$OUT/tun_down.json")"
printf '  %-28s %s\n' "tunnel    uplink   x4:"    "$(fmt_tcp "$OUT/tun_up4.json")"
printf '  %-28s %s\n' "tunnel    downlink x4:"    "$(fmt_tcp "$OUT/tun_down4.json")"
for rate in 1G 2G 4G 8G; do
    printf '  %-28s %s\n' "tunnel    UDP @ $rate:" "$(fmt_udp "$OUT/tun_udp_$rate.json")"
done
echo
echo "JSON + logs in $OUT/"
