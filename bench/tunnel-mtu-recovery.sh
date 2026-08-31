#!/usr/bin/env bash
# End-to-end version of the MTU-recovery test: the same three-phase profile,
# but through a real straw tunnel, measuring what a user would actually see.
#
#   client ──veth── proxy ──veth── origin
#   172.31.0.2    172.31.0.1      10.99.0.2
#
# iperf3 runs REVERSE (origin -> client), so the bulk sender is straw: its QUIC
# path MTU is the one under test, and when it collapses the proxy starts
# dropping oversize packets coming off its TUN — counted in
# straw_packets_mtu_dropped_total.
#
# Phases: [0,T1) clean | [T1,T2) real black hole | [T2,end) 3% random loss.
#
# The counterpart of bench/mtu-recovery.sh, which measures the same thing at
# the QUIC layer. Read that one first: it is the sharper instrument, because it
# samples current_mtu and black_holes_detected directly. This one answers the
# question that matters to a user of straw -- what the tunnel does -- at the
# cost of a noisier signal: TCP's own RTO backoff after the black hole stalls
# the transfer for ~100s in ANY build, so keep the black-hole window short
# (T2-T1) and read the trace after it, not the average over the whole run.
#
#   sudo BIN=target/release bench/tunnel-mtu-recovery.sh [label] [total] [loss%] [T1] [T2]
#
# To A/B it against an unpatched quinn-proto, build a second set of binaries
# with the [patch.crates-io] quinn-proto entry removed from Cargo.toml, into
# their own --target-dir, and point BIN at that.
set -euo pipefail

BIN=${BIN:-target/release}; LABEL=${1:-run}; TOTAL=${2:-240}; LOSS=${3:-3}; T1=${4:-20}; T2=${5:-25}
NS_C=mtue2e_client NS_P=mtue2e_proxy NS_O=mtue2e_origin
ROOT=$(cd "$(dirname "$0")/.." && pwd)
case "$BIN" in /*) ;; *) BIN=$ROOT/$BIN ;; esac
OUT=$ROOT/bench/results/tunnel-mtu-$LABEL
mkdir -p "$OUT"
[ -x "$BIN/straw" ] && [ -x "$BIN/strawc" ] || { echo "build first: cargo build --release --bins (looked in $BIN)"; exit 1; }
command -v iperf3 >/dev/null || { echo "iperf3 not found"; exit 1; }

STRAW_PID=; STRAWC_PID=; IPERF_PID=
cleanup() {
    set +e
    for p in $STRAWC_PID $STRAW_PID $IPERF_PID; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    for _ in $(seq 20); do ip netns pids $NS_C 2>/dev/null | grep -q . || break; sleep 0.1; done
    for ns in $NS_C $NS_P $NS_O; do ip netns del $ns 2>/dev/null; done
    set -e
}
trap cleanup EXIT
cleanup 2>/dev/null || true

pair() { local a="tmp_a$$" b="tmp_b$$"
    ip link add "$a" type veth peer name "$b"
    ip link set "$a" netns "$1" name "$2"; ip link set "$b" netns "$3" name "$4"
    ip netns exec "$1" ip link set "$2" up; ip netns exec "$3" ip link set "$4" up; }

for ns in $NS_C $NS_P $NS_O; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
pair $NS_C veth0 $NS_P veth0
pair $NS_P veth1 $NS_O veth0
ip netns exec $NS_C ip addr add 172.31.0.2/24 dev veth0
ip netns exec $NS_P ip addr add 172.31.0.1/24 dev veth0
ip netns exec $NS_P ip addr add 10.99.0.1/24 dev veth1
ip netns exec $NS_O ip addr add 10.99.0.2/24 dev veth0
ip netns exec $NS_O ip route add default via 10.99.0.1

ip netns exec $NS_P env RUST_LOG=straw=info "$BIN/straw" \
    --listen 0.0.0.0:4433 --tun --nat-interface veth1 \
    --metrics-listen 127.0.0.1:9090 >"$OUT/straw.log" 2>&1 &
STRAW_PID=$!
for _ in $(seq 100); do grep -q "proxy listening" "$OUT/straw.log" && break; sleep 0.1; done

ip netns exec $NS_C env RUST_LOG=straw=info "$BIN/strawc" \
    --server-addr 172.31.0.1:4433 --insecure >"$OUT/strawc.log" 2>&1 &
STRAWC_PID=$!
for _ in $(seq 100); do ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 || { cat "$OUT/strawc.log"; echo "strawc never came up"; exit 1; }
sleep 3   # let path-MTU discovery ramp

ip netns exec $NS_O iperf3 -s -1 -B 10.99.0.2 >/dev/null 2>&1 &
IPERF_PID=$!
sleep 0.3

( sleep "$T1"
  ip netns exec $NS_P iptables -A OUTPUT -p udp -m length --length 1300:65535 -j DROP
  echo "[t=${T1}s] black hole on (proxy drops UDP >=1300B toward client)" >&2
  sleep $((T2 - T1))
  ip netns exec $NS_P iptables -D OUTPUT -p udp -m length --length 1300:65535 -j DROP
  ip netns exec $NS_P tc qdisc add dev veth0 root netem loss "${LOSS}%"
  echo "[t=${T2}s] black hole off, ${LOSS}% loss on" >&2 ) &
SCHED=$!

# Sampler: tunnel MTU as the client sees it, and the proxy's oversize-drop
# counter. A climbing counter means the session MTU has fallen below the
# packets the network is handing the proxy.
( echo "t_s,client_tun_mtu,mtu_dropped,to_client,dropped"
  for i in $(seq 0 "$TOTAL"); do
      m=$(ip netns exec $NS_C cat /sys/class/net/strawc0/mtu 2>/dev/null || echo 0)
      s=$(ip netns exec $NS_P curl -s --max-time 1 http://127.0.0.1:9090/metrics 2>/dev/null || true)
      md=$(echo "$s" | awk '/^straw_packets_mtu_dropped_total /{print $2}')
      tc=$(echo "$s" | awk '/^straw_packets_to_client_total /{print $2}')
      dr=$(echo "$s" | awk '/^straw_packets_dropped_total /{print $2}')
      echo "$i,$m,${md:-0},${tc:-0},${dr:-0}"
      sleep 1
  done ) > "$OUT/samples.csv" &
SAMP=$!

# Reverse: the origin is the sender, so the proxy is the QUIC bulk sender.
ip netns exec $NS_C iperf3 -c 10.99.0.2 -R -t "$TOTAL" -i 5 -b 200M \
    >"$OUT/iperf.txt" 2>&1 || echo "(iperf3 exited non-zero)" >&2

wait $SCHED 2>/dev/null || true
kill $SAMP 2>/dev/null || true
echo "=== $LABEL"
tail -4 "$OUT/iperf.txt"
