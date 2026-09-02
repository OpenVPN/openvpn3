#!/bin/bash
# test_server_stats.sh — ServerEventHandler::on_stats integration test.
#
# Drives the aggregate stats callback end to end and checks the two things a
# unit test cannot: that the numbers describe real traffic, and that they mean
# the same thing on both data paths.
#
# Under kernel DCO the payload never crosses the userspace socket, so the byte
# totals are assembled from two sources -- SessionStats for what userspace saw
# and the kernel's per-peer counters for what it did not. Running the identical
# transfer through both paths and comparing the reported delta is what shows
# the two halves are neither double-counted nor missing (they agreed to within
# one keepalive when this was written).
#
# Modes:
#   classic — userspace data path (--disable-dco)
#   dco     — kernel DCO data path, additionally asserting the ovpn netdev
#
# Prerequisites: root / CAP_NET_ADMIN, ovpnserv and a CLI_OVPNDCO=ON ovpncli,
# and for `dco` a loadable mainline `ovpn` module.
#
# Usage: sudo ./test_server_stats.sh [BUILD_DIR] [classic|dco]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"
MODE="${2:-classic}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpncli"
SSL_DIR="${CORE_ROOT}/test/ssl"

# Namespace and link names derive from the mode so the scenarios run in
# parallel under ctest. Kept short: link names are IFNAMSIZ-bound.
case "${MODE}" in
classic) SUFFIX=cl SERVER_PORT=11394 ;;
dco) SUFFIX=dco SERVER_PORT=11395 ;;
*)
    echo "unknown mode: ${MODE} (expected classic|dco)" >&2
    exit 2
    ;;
esac

NS_SERVER="ns-stats-${SUFFIX}-s"
NS_CLIENT="ns-stats-${SUFFIX}-c"
VETH_SERVER="vst${SUFFIX}s"
VETH_CLIENT="vst${SUFFIX}c"
SERVER_VETH_IP="192.168.94.1"
CLIENT_VETH_IP="192.168.94.2"

TUNNEL_SERVER_IP="10.8.0.1"
HANDSHAKE_TIMEOUT="$(scaled 20)"
STATS_INTERVAL=2

# Short enough that the reaper notices a vanished client inside the test's
# runtime: ovpncli killed with SIGTERM sends no exit notification, so the
# session lives until the keepalive timeout, and the client count only returns
# to zero once it does.
KEEPALIVE_PING=2
KEEPALIVE_TIMEOUT=8

# A payload large enough that encapsulation overhead cannot be mistaken for it.
PING_COUNT=200
PING_SIZE=1000
PAYLOAD_MIN=$((PING_COUNT * PING_SIZE))

# Scoped by uid: `classic` needs no privilege of its own, so a prior sudo run
# must not leave a root-owned log dir behind for an unprivileged one.
LOG_DIR="/tmp/vpn-server-stats-it-$(id -u)-${MODE}"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
CLIENT_CFG="${LOG_DIR}/client.ovpn"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${CLIENT_PID}" ]] && kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    [[ -n "${CLIENT_PID}" ]] && kill -9 "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    netns_teardown "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}"
}
trap cleanup EXIT

# Last reported value for one field of the "stats:" log line.
last_stat() {
    local field="$1"
    grep "stats:" "${SERVER_LOG}" | tail -1 | grep -oP "\\d+(?= ${field})" || echo ""
}

stats_line_count() {
    grep -c "stats:" "${SERVER_LOG}" 2>/dev/null || true
}

# Wait until at least $1 stats reports have been logged.
wait_for_reports() {
    local want="$1" deadline=$((SECONDS + $(scaled 30)))
    while ((SECONDS < deadline)); do
        [[ "$(stats_line_count)" -ge "${want}" ]] && return 0
        sleep 1
    done
    return 1
}

# Wait until one field of the latest report reaches $2, and for a further
# report after it, so the value read is a settled one rather than mid-change.
wait_for_stat() {
    local field="$1" want="$2" deadline=$((SECONDS + $(scaled 40)))
    while ((SECONDS < deadline)); do
        if [[ "$(last_stat "${field}")" == "${want}" ]]; then
            local n
            n="$(stats_line_count)"
            wait_for_reports $((n + 1)) || return 1
            [[ "$(last_stat "${field}")" == "${want}" ]] && return 0
        fi
        sleep 1
    done
    return 1
}

# Wait until the cumulative rx and tx totals have both advanced by $1.
wait_for_bytes() {
    local delta="$1" base_rx="$2" base_tx="$3"
    local deadline=$((SECONDS + $(scaled 40)))
    while ((SECONDS < deadline)); do
        local rx tx
        rx="$(last_stat rx)"
        tx="$(last_stat tx)"
        if [[ -n "${rx}" && -n "${tx}" ]] \
            && ((rx - base_rx >= delta)) && ((tx - base_tx >= delta)); then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo "=== Server stats integration test (${MODE}) ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        exit 77
    fi
fi

DCO_ARGS=()
if [[ "${MODE}" == "dco" ]]; then
    if ! modprobe -n ovpn 2>/dev/null || ! modprobe ovpn 2>/dev/null; then
        echo "SKIP: mainline ovpn kernel module not available"
        exit 77
    fi
    echo "      ovpn module loaded"
else
    DCO_ARGS=(--disable-dco)
fi

for bin in "${SERV_BIN}" "${CLI_BIN}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "SKIP: binary not found at ${bin}"
        exit 77
    fi
done
require_ping

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

echo "[1/7] Starting ovpnserv with --stats-interval ${STATS_INTERVAL}..."
ns_bg "${NS_SERVER}" "${SERV_BIN}" \
    --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
    --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_VETH_IP}" --port "${SERVER_PORT}" \
    --stats-interval "${STATS_INTERVAL}" \
    --keepalive "${KEEPALIVE_PING}" "${KEEPALIVE_TIMEOUT}" \
    "${DCO_ARGS[@]}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately" "${SERVER_LOG}" "${CLIENT_LOG}"
fi

if [[ "${MODE}" == "dco" ]]; then
    if ! ns_exec "${NS_SERVER}" ip -d link show type ovpn 2>/dev/null | grep -q .; then
        fail "No ovpn-type netdev -- this mode must measure the kernel path" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    echo "      ovpn-type netdev present"
fi

# ── The callback fires on its own, with no client ─────────────────────

echo "[2/7] Waiting for stats reports with no clients connected..."
if ! wait_for_reports 2; then
    fail "Expected repeated stats reports, saw $(stats_line_count)" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
IDLE_LINES="$(stats_line_count)"
if [[ "$(last_stat clients)" != "0" ]]; then
    fail "Reported $(last_stat clients) clients before any connected" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      ${IDLE_LINES} reports, 0 clients, $(last_stat rx) rx"

# ── One client raises the count ───────────────────────────────────────

echo "[3/7] Connecting a client..."
cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto udp4
remote ${SERVER_VETH_IP} ${SERVER_PORT}
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/client.crt
key ${SSL_DIR}/client.key
EOF

ns_bg "${NS_CLIENT}" "${CLI_BIN}" "${CLIENT_CFG}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

if ! wait_for_connected "${CLIENT_LOG}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
    fail "Client did not complete handshake within ${HANDSHAKE_TIMEOUT}s" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi

if ! wait_for_stat clients 1; then
    fail "Reported $(last_stat clients) clients with one connected" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
BASE_RX="$(last_stat rx)"
BASE_TX="$(last_stat tx)"
echo "      1 client, handshake accounted: rx=${BASE_RX} tx=${BASE_TX}"

if [[ "${BASE_RX}" -eq 0 || "${BASE_TX}" -eq 0 ]]; then
    fail "Handshake traffic was not counted" "${SERVER_LOG}" "${CLIENT_LOG}"
fi

# ── Payload moves the byte totals, on either data path ────────────────

echo "[4/7] Pushing ${PING_COUNT}x${PING_SIZE}B through the tunnel..."
ns_exec "${NS_CLIENT}" ping -c "${PING_COUNT}" -i 0.01 -s "${PING_SIZE}" -W 2 \
    "${TUNNEL_SERVER_IP}" >"${LOG_DIR}/ping.log" 2>&1 || true

if ! wait_for_bytes "${PAYLOAD_MIN}" "${BASE_RX}" "${BASE_TX}"; then
    fail "Byte totals did not account for the payload within the timeout (rx=$(last_stat rx) tx=$(last_stat tx), baseline rx=${BASE_RX} tx=${BASE_TX}, expected +${PAYLOAD_MIN})" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi

PAY_RX="$(last_stat rx)"
PAY_TX="$(last_stat tx)"
DELTA_RX=$((PAY_RX - BASE_RX))
DELTA_TX=$((PAY_TX - BASE_TX))
echo "      delta: rx=${DELTA_RX} tx=${DELTA_TX} (payload was ${PAYLOAD_MIN} each way)"

# Reaching the payload is the wait's postcondition; what remains to check is
# that the total did not overshoot it, which is what a double count looks like.
if [[ "${DELTA_RX}" -gt $((PAYLOAD_MIN * 3 / 2)) || "${DELTA_TX}" -gt $((PAYLOAD_MIN * 3 / 2)) ]]; then
    fail "Byte totals far exceed the payload (rx=${DELTA_RX} tx=${DELTA_TX}) -- double counted?" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi

# ── Totals are cumulative, not a live sum ─────────────────────────────

echo "[5/7] Disconnecting the client..."
kill -TERM "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""

if ! wait_for_stat clients 0; then
    fail "Client count did not return to 0 after the session ended (got $(last_stat clients))" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      0 clients"

echo "[6/7] Checking the byte totals survived the disconnect..."
GONE_RX="$(last_stat rx)"
GONE_TX="$(last_stat tx)"
if [[ "${GONE_RX}" -lt "${PAY_RX}" || "${GONE_TX}" -lt "${PAY_TX}" ]]; then
    fail "Totals dropped when the client left (rx ${PAY_RX} -> ${GONE_RX}, tx ${PAY_TX} -> ${GONE_TX})" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      rx=${GONE_RX} tx=${GONE_TX}, retained"

# ── Monotonic across every report ─────────────────────────────────────

echo "[7/7] Checking every report is monotonic..."
if ! awk '/stats:/ {
        for (i = 1; i <= NF; i++) {
            if ($(i+1) == "rx") rx = $i
            if ($(i+1) == "tx") tx = $i
        }
        if (rx < prx || tx < ptx) {
            printf "report %d went backwards: rx %d -> %d, tx %d -> %d\n", NR, prx, rx, ptx, tx
            bad = 1
        }
        prx = rx; ptx = tx
    }
    END { exit bad }' "${SERVER_LOG}"; then
    fail "Byte totals are not monotonic" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      $(stats_line_count) reports, none regressed"

echo ""
echo "=== PASSED (${MODE}) ==="
echo "    Reports: $(stats_line_count) at ${STATS_INTERVAL}s"
echo "    Payload delta: rx=${DELTA_RX} tx=${DELTA_TX} for ${PAYLOAD_MIN} each way"
echo "    Final: rx=${GONE_RX} tx=${GONE_TX}, 0 clients"
echo "    Logs: ${LOG_DIR}/"
