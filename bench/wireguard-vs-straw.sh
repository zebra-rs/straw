#!/usr/bin/env bash
# WireGuard vs straw (MASQUE CONNECT-IP): same host, same topology, same runs.
#
# The point of this script is comparability, not a WireGuard benchmark. Both
# tunnels are brought up in the *same* three namespaces, back to back, and
# driven by the same iperf3 profile, so the only difference between the two
# legs is the tunnel itself. The raw-veth ceiling is measured in the same
# session and bounds both.
#
#   client ──veth── proxy ──veth── origin
#   172.31.0.2    172.31.0.1      10.99.0.2
#                 10.99.0.1 (SNAT out veth1)
#
#   straw leg:     strawc TUN ─ QUIC/H3 datagrams ─ straw TUN ─ NAT ─ origin
#   wireguard leg: wg0        ─ WireGuard UDP     ─ wg0        ─ NAT ─ origin
#
# The confound this CANNOT remove, and which dominates the result: WireGuard
# here is the **in-kernel** implementation, straw is **userspace**. No
# userspace WireGuard (wireguard-go/boringtun) is installed on this host, so
# the measured gap is kernel-vs-userspace at least as much as it is
# WireGuard-vs-MASQUE. Read the numbers with that in mind; see
# wireguard-comparison.md.
#
#   sudo bench/wireguard-vs-straw.sh [duration_seconds]
#   sudo MTU_SWEEP=1 bench/wireguard-vs-straw.sh   # + the packet-rate diagnosis
#   sudo WG_MTU=1440 bench/wireguard-vs-straw.sh   # WireGuard's natural width
set -euo pipefail

DUR=${1:-10}
NS_C=wgbench_client
NS_P=wgbench_proxy
NS_O=wgbench_origin
BIN=${BIN:-target/release}
OUT=bench/results/wg
mkdir -p "$OUT"

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run under sudo (needs netns + TUN + wireguard)"
[ -x "$BIN/straw" ] && [ -x "$BIN/strawc" ] || fail "build first: cargo build --release --bins"
command -v iperf3 >/dev/null || fail "iperf3 not found"
command -v jq >/dev/null || fail "jq not found"
command -v wg >/dev/null || fail "wg(8) not found"

STRAWC_PID=; STRAW_PID=
cleanup() {
    set +e
    for p in $STRAWC_PID $STRAW_PID; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
    for _ in $(seq 20); do ip netns pids $NS_C 2>/dev/null | grep -q . || break; sleep 0.1; done
    for ns in $NS_C $NS_P $NS_O; do ip netns del $ns 2>/dev/null; done
    set -e
}
trap cleanup EXIT
cleanup 2>/dev/null || true

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
pair $NS_C veth0 $NS_P veth0
pair $NS_P veth1 $NS_O veth0
ip netns exec $NS_C ip addr add 172.31.0.2/24 dev veth0
ip netns exec $NS_P ip addr add 172.31.0.1/24 dev veth0
ip netns exec $NS_P ip addr add 10.99.0.1/24 dev veth1
ip netns exec $NS_O ip addr add 10.99.0.2/24 dev veth0
ip netns exec $NS_O ip route add default via 10.99.0.1

# --- run helpers -------------------------------------------------------------

# Whole-box CPU across one run. The kernel WireGuard data plane has no process
# of its own (it runs in softirq and per-peer kernel workqueues), so per-process
# accounting cannot compare the two legs; busy cores can.
cpu_snapshot() { awk '/^cpu /{idle=$5+$6; tot=0; for(i=2;i<=NF;i++) tot+=$i; print tot, idle}' /proc/stat; }
cpu_delta() { # "tot idle" before -> cores busy
    local b=($1) a=($(cpu_snapshot))
    awk -v t0="${b[0]}" -v i0="${b[1]}" -v t1="${a[0]}" -v i1="${a[1]}" -v n="$(nproc)" \
        'BEGIN{dt=t1-t0; if(dt<=0){print "n/a"; exit} printf "%.2f", (1-(i1-i0)/dt)*n}'
}

# tx bytes + tx packets for one device in the client namespace.
snap() { ip netns exec $NS_C awk -v d="$1:" '$1==d{print $10, $11}' /proc/net/dev; }

# TUN_DEV is the leg's inner device; the outer device is always veth0. Counting
# both is what separates "this tunnel is slow" from "this tunnel puts five
# times as many skbs through the kernel", which is the actual difference.
TUN_DEV=

run() { # label server_ns server_ip client_ns [flags...]
    local label=$1 sns=$2 sip=$3 cns=$4; shift 4
    ip netns exec "$sns" iperf3 -s -1 -B "$sip" >/dev/null 2>&1 &
    local spid=$!
    sleep 0.3
    local c0=$(cpu_snapshot) v0=$(snap veth0) t0=
    [ -n "$TUN_DEV" ] && t0=$(snap "$TUN_DEV")
    if ip netns exec "$cns" iperf3 -c "$sip" -t "$DUR" -J "$@" \
         >"$OUT/${label}.json" 2>"$OUT/${label}.err"; then :; else
        echo "  ($label failed: $(head -1 "$OUT/${label}.err"))"
    fi
    cpu_delta "$c0" > "$OUT/${label}.cpu"
    { pps "$v0" "$(snap veth0)"; [ -n "$TUN_DEV" ] && pps "$t0" "$(snap "$TUN_DEV")"; } \
        > "$OUT/${label}.pps"
    kill "$spid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
}

# "<pps> <avg bytes>" from two "<tx bytes> <tx packets>" snapshots.
pps() {
    local b=($1) a=($2)
    awk -v b0="${b[0]}" -v p0="${b[1]}" -v b1="${a[0]}" -v p1="${a[1]}" -v d="$DUR" \
        'BEGIN{dp=p1-p0; if(dp<=0){print "0 0"; exit} printf "%.0f %.0f\n", dp/d, (b1-b0)/dp}'
}

fmt_tcp() { jq -r 'if .end.sum_received then (.end.sum_received.bits_per_second/1e9) else 0 end
                   | "\(.*100|round/100) Gbit/s"' "$1" 2>/dev/null || echo "n/a"; }
fmt_udp() { jq -r '"\(.end.sum.bits_per_second/1e9*100|round/100) Gbit/s, loss \(.end.sum.lost_percent*100|round/100)%"' "$1" 2>/dev/null || echo "n/a"; }
cpu_of()  { cat "$OUT/$1.cpu" 2>/dev/null || echo "n/a"; }

row() { printf '  %-30s %-24s cores busy %s\n' "$1" "$(fmt_tcp "$OUT/$2.json")" "$(cpu_of "$2")"; }
skbs() { # label run -- "outer <pps> avg <B>  inner <pps> avg <B>"
    local o=($(sed -n 1p "$OUT/$2.pps" 2>/dev/null)) i=($(sed -n 2p "$OUT/$2.pps" 2>/dev/null))
    printf '  %-30s outer %7s skbs/s avg %6s B' "$1" "${o[0]:-n/a}" "${o[1]:-n/a}"
    [ -n "${i[0]:-}" ] && printf '   inner %7s skbs/s avg %6s B' "${i[0]}" "${i[1]}"
    printf '\n'
}

# --- leg 0: the shared ceiling ----------------------------------------------

log "TCP: raw veth ceiling (client <-> proxy, no tunnel)"
run veth_up   $NS_P 172.31.0.1 $NS_C
run veth_down $NS_P 172.31.0.1 $NS_C -R

# --- leg 1: straw ------------------------------------------------------------

log "straw: proxy + client"
ip netns exec $NS_P env RUST_LOG=straw=info "$BIN/straw" \
    --listen 0.0.0.0:4433 --tun --nat-interface veth1 >"$OUT/straw.log" 2>&1 &
STRAW_PID=$!
for _ in $(seq 100); do grep -q "proxy listening" "$OUT/straw.log" && break; sleep 0.1; done
grep -q "proxy listening" "$OUT/straw.log" || { cat "$OUT/straw.log"; fail "straw did not start"; }

ip netns exec $NS_C env RUST_LOG=straw=info "$BIN/strawc" \
    --server-addr 172.31.0.1:4433 --insecure >"$OUT/strawc.log" 2>&1 &
STRAWC_PID=$!
for _ in $(seq 100); do ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 && break; sleep 0.1; done
ip netns exec $NS_C ip link show strawc0 >/dev/null 2>&1 || { cat "$OUT/strawc.log"; fail "strawc0 never appeared"; }
sleep 3   # let quinn's path MTU ramp so the tunnel runs at full width
STRAW_MTU=$(ip netns exec $NS_C cat /sys/class/net/strawc0/mtu)
TUN_DEV=strawc0
echo "  strawc0 MTU $STRAW_MTU"

log "TCP: through straw"
run straw_up    $NS_O 10.99.0.2 $NS_C
run straw_down  $NS_O 10.99.0.2 $NS_C -R
run straw_up4   $NS_O 10.99.0.2 $NS_C -P 4
run straw_down4 $NS_O 10.99.0.2 $NS_C -R -P 4
log "UDP: through straw"
for rate in 1G 4G; do run "straw_udp_$rate" $NS_O 10.99.0.2 $NS_C -u -b "$rate"; done

log "straw: teardown"
kill $STRAWC_PID 2>/dev/null || true; wait $STRAWC_PID 2>/dev/null || true
kill $STRAW_PID  2>/dev/null || true; wait $STRAW_PID  2>/dev/null || true
STRAWC_PID=; STRAW_PID=
# strawc reverts its own routes on exit; make sure nothing it left behind
# steers the WireGuard leg.
ip netns exec $NS_C ip route flush dev strawc0 2>/dev/null || true
ip netns exec $NS_C ip route show | grep -q '^default' && ip netns exec $NS_C ip route del default 2>/dev/null || true

# --- leg 2: wireguard --------------------------------------------------------
#
# Matched to straw's live tunnel MTU by default so the two legs carry the same
# payload per packet; WG_MTU=1440 is WireGuard's natural width here
# (1500 - 20 IPv4 - 8 UDP - 32 WireGuard).
WG_MTU=${WG_MTU:-$STRAW_MTU}

log "wireguard: interfaces (MTU $WG_MTU)"
KEY_C=$(wg genkey); PUB_C=$(printf %s "$KEY_C" | wg pubkey)
KEY_P=$(wg genkey); PUB_P=$(printf %s "$KEY_P" | wg pubkey)
# Scoped to the keys: a bare `umask 077` here would also make every result
# file root-only, since the whole script runs under sudo.
( umask 077; printf %s "$KEY_C" > "$OUT/c.key"; printf %s "$KEY_P" > "$OUT/p.key" )

for spec in "$NS_C 10.98.0.2 $OUT/c.key" "$NS_P 10.98.0.1 $OUT/p.key"; do
    set -- $spec
    ip -n "$1" link add wg0 type wireguard
    ip -n "$1" addr add "$2/24" dev wg0
    ip netns exec "$1" wg set wg0 private-key "$3"
    ip -n "$1" link set wg0 mtu "$WG_MTU" up
done
ip netns exec $NS_P wg set wg0 listen-port 51820 \
    peer "$PUB_C" allowed-ips 10.98.0.2/32
ip netns exec $NS_C wg set wg0 \
    peer "$PUB_P" allowed-ips 0.0.0.0/0 endpoint 172.31.0.1:51820 persistent-keepalive 25
# AllowedIPs 0.0.0.0/0 would swallow the tunnel's own endpoint; pin it to veth0
# first, then default into wg0 (what wg-quick does with fwmark, done by hand).
ip netns exec $NS_C ip route add 172.31.0.1/32 dev veth0
ip netns exec $NS_C ip route add default dev wg0

log "wireguard: proxy forwarding + NAT"
ip netns exec $NS_P sysctl -qw net.ipv4.ip_forward=1
ip netns exec $NS_P iptables -t nat -A POSTROUTING -s 10.98.0.0/24 -o veth1 -j MASQUERADE
ip netns exec $NS_C ping -c1 -W2 10.99.0.2 >/dev/null 2>&1 || fail "wireguard tunnel does not pass traffic"
TUN_DEV=wg0

log "TCP: through wireguard"
run wg_up    $NS_O 10.99.0.2 $NS_C
run wg_down  $NS_O 10.99.0.2 $NS_C -R
run wg_up4   $NS_O 10.99.0.2 $NS_C -P 4
run wg_down4 $NS_O 10.99.0.2 $NS_C -R -P 4
log "UDP: through wireguard"
for rate in 1G 4G; do run "wg_udp_$rate" $NS_O 10.99.0.2 $NS_C -u -b "$rate"; done

# --- optional: is the slow leg packet-bound or byte-bound? --------------------
#
# MTU_SWEEP=1 re-runs the WireGuard leg at three tunnel MTUs, widening the
# veths to match. If throughput tracks packet *size* at a flat packet *rate*,
# nothing byte-proportional (cipher, copies) is the constraint — the per-packet
# kernel traversal is.
if [ "${MTU_SWEEP:-}" = 1 ]; then
    log "wireguard: MTU sweep"
    for VMTU in 1412 1440 8920; do
        OUTER=$((VMTU + 80))
        for spec in "$NS_C veth0" "$NS_P veth0" "$NS_P veth1" "$NS_O veth0"; do
            set -- $spec; ip netns exec "$1" ip link set "$2" mtu "$OUTER"
        done
        ip -n $NS_C link set wg0 mtu "$VMTU"; ip -n $NS_P link set wg0 mtu "$VMTU"
        ip netns exec $NS_C ping -c1 -W2 10.99.0.2 >/dev/null 2>&1 || { echo "  mtu $VMTU: no traffic"; continue; }
        run "wg_sweep_$VMTU" $NS_O 10.99.0.2 $NS_C
        printf '  mtu %-5s %-22s %s\n' "$VMTU" "$(fmt_tcp "$OUT/wg_sweep_$VMTU.json")" \
            "$(sed -n 2p "$OUT/wg_sweep_$VMTU.pps" | awk '{printf "wg0 %s pkt/s, avg %s B", $1, $2}')"
    done
    # Where the cycles went. One core near 100% %soft with the rest idle means a
    # single-flow softirq wall, not a protocol limit.
    if command -v mpstat >/dev/null; then
        log "wireguard: per-CPU spread (one 6 s run)"
        ip -n $NS_C link set wg0 mtu "$STRAW_MTU"; ip -n $NS_P link set wg0 mtu "$STRAW_MTU"
        ip netns exec $NS_O iperf3 -s -1 -B 10.99.0.2 >/dev/null 2>&1 &
        sp=$!; sleep 0.3
        mpstat -P ALL 6 1 2>/dev/null | awk '/^Average/ && ($3=="CPU" || $2=="all" || $NF+0 < 50)' &
        ip netns exec $NS_C iperf3 -c 10.99.0.2 -t 6 >/dev/null 2>&1
        wait
        kill $sp 2>/dev/null || true
    fi
fi

# --- results -----------------------------------------------------------------

log "results ($DUR s each; straw MTU $STRAW_MTU, wireguard MTU $WG_MTU, $(nproc) cores)"
row "raw veth      uplink:"        veth_up
row "raw veth      downlink (-R):" veth_down
echo
row "straw         uplink:"        straw_up
row "straw         downlink (-R):" straw_down
row "straw         uplink   x4:"   straw_up4
row "straw         downlink x4:"   straw_down4
echo
row "wireguard     uplink:"        wg_up
row "wireguard     downlink (-R):" wg_down
row "wireguard     uplink   x4:"   wg_up4
row "wireguard     downlink x4:"   wg_down4
echo
# The crux: how many times does each leg traverse the kernel's packet path?
skbs "straw         uplink skbs:"     straw_up
skbs "wireguard     uplink skbs:"     wg_up
echo
for rate in 1G 4G; do
    printf '  %-30s %s\n' "straw     UDP @ $rate:" "$(fmt_udp "$OUT/straw_udp_$rate.json")"
    printf '  %-30s %s\n' "wireguard UDP @ $rate:" "$(fmt_udp "$OUT/wg_udp_$rate.json")"
done
echo
echo "  NOTE: kernel WireGuard vs userspace straw. The gap is kernel-vs-userspace"
echo "        as much as it is WireGuard-vs-MASQUE. See wireguard-comparison.md."
echo
echo "JSON + logs in $OUT/"
