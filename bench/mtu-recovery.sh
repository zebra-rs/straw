#!/usr/bin/env bash
# Does a QUIC connection recover its path MTU after a black-hole detection,
# while a lossy transfer continues?
#
# This is an A/B: the same probe binary is built twice, against the
# quinn-proto *release* and against the `0.11.x` branch this repo pins (see
# UPSTREAM.md entry 1), and run through the identical three-phase profile.
#
#   sender ──veth── receiver          loss applied to the sender's egress,
#   10.77.0.2      10.77.0.1          because black-hole detection is driven
#                                     by the sender's own lost packets.
#
#   [0,  T1)  clean           -> MTUD raises the path MTU to 1452
#   [T1, T2)  real black hole -> UDP >=1300B dropped
#   [T2, end) LOSS% random    -> ordinary bulk-transfer loss at the floor.
#             The release build judges floor-size loss bursts suspicious
#             (`1200 < 1200` is false), keeps re-firing the detector, and so
#             never leaves min_mtu. The branch build treats them as benign.
#
#   sudo -E env PATH="$PATH" bench/mtu-recovery.sh [total] [loss%] [T1] [T2]
#
# -E is not optional: the fixed variant is a git dependency, and root has no
# CARGO_HOME of its own here.
set -euo pipefail

TOTAL=${1:-200}; LOSS=${2:-3}; T1=${3:-20}; T2=${4:-40}
RATE=${RATE:-200}          # Mbit/s; an unpaced sender makes its own queue loss
NS_S=mtuprobe_snd NS_R=mtuprobe_rcv
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/bench/results/mtu-recovery
# Two dotted keys, not one inline table: `cargo --config` rejects inline tables.
PATCH_GIT='patch.crates-io.quinn-proto.git="https://github.com/quinn-rs/quinn"'
PATCH_BRANCH='patch.crates-io.quinn-proto.branch="0.11.x"'

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run under sudo (needs netns)"
command -v cargo >/dev/null || fail "cargo not on PATH — use: sudo -E env PATH=\"\$PATH\" $0"
command -v iptables >/dev/null || fail "iptables not found"
mkdir -p "$OUT"

log "building both probe variants"
cargo build --release --quiet --manifest-path "$ROOT/bench/mtuprobe/Cargo.toml" \
    --target-dir "$OUT/target-release"
cargo build --release --quiet --manifest-path "$ROOT/bench/mtuprobe/Cargo.toml" \
    --target-dir "$OUT/target-branch" --config "$PATCH_GIT" --config "$PATCH_BRANCH"

cleanup() { set +e; ip netns del $NS_S 2>/dev/null; ip netns del $NS_R 2>/dev/null; set -e; }
trap cleanup EXIT

run() { # variant_label binary
    local label=$1 bin=$2 csv="$OUT/$1.csv"
    cleanup 2>/dev/null || true
    ip netns add $NS_S; ip netns add $NS_R
    ip link add vs type veth peer name vr
    ip link set vs netns $NS_S; ip link set vr netns $NS_R
    ip netns exec $NS_S ip addr add 10.77.0.2/24 dev vs
    ip netns exec $NS_R ip addr add 10.77.0.1/24 dev vr
    ip netns exec $NS_S ip link set vs up mtu 1500
    ip netns exec $NS_R ip link set vr up mtu 1500
    ip netns exec $NS_S ip link set lo up; ip netns exec $NS_R ip link set lo up

    ip netns exec $NS_R "$bin" server 10.77.0.1:4433 >/dev/null 2>&1 &
    local srv=$!
    sleep 1

    ( sleep "$T1"
      ip netns exec $NS_S iptables -A OUTPUT -p udp -m length --length 1300:65535 -j DROP
      sleep $((T2 - T1))
      ip netns exec $NS_S iptables -D OUTPUT -p udp -m length --length 1300:65535 -j DROP
      ip netns exec $NS_S tc qdisc add dev vs root netem loss "${LOSS}%" ) &
    local sched=$!

    ip netns exec $NS_S "$bin" client 10.77.0.1:4433 "$TOTAL" "$RATE" >"$csv" 2>"$csv.summary"
    wait $sched 2>/dev/null || true
    kill $srv 2>/dev/null || true

    awk -F, -v label="$label" -v t1="$T1" '
        NR == 1 { next }
        { n++; if ($2 <= 1200) floor++; last_mtu = $2; last_bh = $3
          if ($1 > t1 && $2 < 1452 && !collapse) collapse = $1 }
        END { printf "  %-22s final MTU %4d | black holes %6d | collapsed at %s | %2d%% of run at the floor\n",
                     label, last_mtu, last_bh, (collapse ? "t=" collapse "s" : "never"), floor*100/n }
    ' "$csv"
}

# The detector re-arms only after MtuDiscoveryConfig::black_hole_cooldown,
# which is 60s. A run that ends before the loss phase has outlasted that shows
# "never collapsed" for BOTH builds and proves nothing.
if [ "$((TOTAL - T2))" -lt 120 ]; then
    echo "  note: only $((TOTAL - T2))s of loss phase; the effect needs >=120s (60s cooldown). Results below are not conclusive."
fi

log "three phases: ${T1}s clean, $((T2-T1))s black hole, $((TOTAL-T2))s at ${LOSS}% loss"
run "quinn-proto release" "$OUT/target-release/release/mtuprobe"
run "quinn-proto 0.11.x"  "$OUT/target-branch/release/mtuprobe"
echo
echo "  per-sample traces: $OUT/*.csv"
