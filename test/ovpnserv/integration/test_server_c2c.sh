#!/bin/bash
# test_server_c2c.sh -- client-to-client policy on the classic data path.
#
# Four scenarios, one per invocation so each is its own ctest entry and a
# failure names the case:
#
#   deny      client_to_client off (default). Each client reaches the server's
#             tunnel address; neither reaches the other's.
#   allow     --client-to-client. Clients reach each other.
#   spoof     client_to_client off, and client-0 sources from an address
#             outside the pool. should_forward() sees an unresolvable source
#             and would forward it; the ingress reverse-path check in
#             TunReal::TunSend must drop it first.
#
#             Asserted on the *server's* tun device, not on client-1 and not
#             on ping exit status. Both of those are confounded: a forged
#             source has no return path so the ping always fails, and fresh
#             namespaces inherit rp_filter=2, so the kernel drops the packet
#             on tun re-ingress even when the server did forward it. The
#             first version of this test watched client-1 and passed with the
#             reverse-path check deleted. The server's tun is the honest
#             observation point, because the check runs before the device
#             write: if it works, the packet never reaches the device at all.
#   spoof-allow
#             --client-to-client with the same forged source. Proves the drop
#             is the reverse-path check and not the c2c policy: legitimate
#             traffic flows in this configuration, the forged source still
#             must not.
#
# Needs two clients, hence lib.sh's bridge topology rather than a veth pair.
#
# Prerequisites: root/CAP_NET_ADMIN (tun device, namespaces), ovpnserv and
# ovpncli built. Self-escalates via passwordless sudo, else skips with 77.
#
# Usage: sudo ./test_server_c2c.sh [BUILD_DIR] [deny|allow|spoof|spoof-allow]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"
MODE="${2:-deny}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpncli"
SSL_DIR="${CORE_ROOT}/test/ssl"

PREFIX="$(case "${MODE}" in deny) echo c2cd ;; allow) echo c2ca ;; spoof) echo c2cs ;; spoof-allow) echo c2csa ;; deny-dco) echo c2cdd ;; allow-dco) echo c2cad ;; esac)"   # kept short: link names are IFNAMSIZ-bound (see lib.sh mc_link)
SUBNET="192.168.94"
N_CLIENTS=2
GATEWAY="10.8.0.1"
SPOOFED_SRC="192.0.2.77" # TEST-NET-1, outside any pool this server hands out

case "${MODE}" in
deny) PORT=11594 ;;
allow) PORT=11595 ;;
spoof) PORT=11596 ;;
spoof-allow) PORT=11597 ;;
deny-dco) PORT=11598 ;;
allow-dco) PORT=11599 ;;
*)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

HANDSHAKE_TIMEOUT="$(scaled 15)"
LOG_DIR="/tmp/vpn-server-c2c-it-${MODE}"

NS_SERVER="$(mc_ns_server "${PREFIX}")"
NS_C0="$(mc_ns_client "${PREFIX}" 0)"
NS_C1="$(mc_ns_client "${PREFIX}" 1)"
SERVER_LOG="${LOG_DIR}/server.log"
SERVER_PID=""
CLIENT_PIDS=()
TCPDUMP_PID=""

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${TCPDUMP_PID}" ]] && kill -TERM "${TCPDUMP_PID}" 2>/dev/null || true
    local pid
    for pid in "${CLIENT_PIDS[@]:-}"; do
        [[ -n "${pid}" ]] && kill -TERM "${pid}" 2>/dev/null || true
    done
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    for pid in "${CLIENT_PIDS[@]:-}"; do
        [[ -n "${pid}" ]] && kill -9 "${pid}" 2>/dev/null || true
    done
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    mc_teardown "${PREFIX}" "${N_CLIENTS}"
}
trap cleanup EXIT

echo "=== Server client-to-client integration test -- mode: ${MODE} ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        exit 77
    fi
fi

for bin in "${SERV_BIN}" "${CLI_BIN}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "SKIP: binary not found at ${bin}"
        exit 77
    fi
done
require_ping
if ! command -v tcpdump >/dev/null 2>&1 && [[ "${MODE}" == spoof* ]]; then
    echo "SKIP: tcpdump required to observe the spoofed-source drop"
    exit 77
fi
if [[ "${MODE}" == *-dco ]]; then
    if ! modprobe -n ovpn 2>/dev/null; then
        echo "SKIP: mainline ovpn kernel module not available"
        exit 77
    fi
    modprobe ovpn 2>/dev/null || {
        echo "SKIP: failed to load ovpn kernel module"
        exit 77
    }
fi

mkdir -p "${LOG_DIR}"
rm -f "${LOG_DIR}"/*.log "${LOG_DIR}"/*.ovpn "${LOG_DIR}"/*.pcap

# ── Topology ─────────────────────────────────────────────────────────

echo "[1/5] Building bridge topology: 1 server + ${N_CLIENTS} clients..."
mc_setup "${PREFIX}" "${SUBNET}" "${N_CLIENTS}"
SERVER_IP="$(mc_server_ip "${PREFIX}" "${SUBNET}")"
echo "      server ${SERVER_IP}, clients $(mc_client_ip "${PREFIX}" "${SUBNET}" 0) / $(mc_client_ip "${PREFIX}" "${SUBNET}" 1)"

# ── Server ───────────────────────────────────────────────────────────

C2C_ARGS=()
case "${MODE}" in
allow | spoof-allow | allow-dco) C2C_ARGS=(--client-to-client) ;;
esac

# The -dco modes exist because client-to-client enforcement moved into netfilter
# (netpolicy.hpp), which attaches to whichever netdev the active data path
# created. That makes the policy datapath-independent in principle; these modes
# are what actually demonstrate it on the kernel DCO netdev rather than only on
# the classic tun.
DP_ARGS=(--disable-dco)
DP_LABEL="classic"
if [[ "${MODE}" == *-dco ]]; then
    DP_ARGS=()
    DP_LABEL="kernel DCO"
fi

echo "[2/5] Starting ${DP_LABEL} ovpnserv${C2C_ARGS[0]:+ ${C2C_ARGS[0]}}..."
ns_bg "${NS_SERVER}" "${SERV_BIN}" \
    --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
    --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_IP}" --port "${PORT}" "${DP_ARGS[@]}" \
    "${C2C_ARGS[@]}" \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2
kill -0 "${SERVER_PID}" 2>/dev/null || fail "Server exited immediately" "${SERVER_LOG}" /dev/null
echo "      Server PID: ${SERVER_PID}"

# A -dco mode that silently fell back to the classic tun would still pass every
# assertion below while proving nothing about the DCO netdev, so confirm which
# data path came up before testing policy on it.
if [[ "${MODE}" == *-dco ]]; then
    if ! ns_exec "${NS_SERVER}" ip -d link show type ovpn 2>/dev/null | grep -q .; then
        fail "no ovpn-type netdev: DCO did not engage, so this mode would not be testing it" \
            "${SERVER_LOG}" /dev/null
    fi
    echo "      kernel DCO engaged (ovpn-type netdev present)"
else
    if ns_exec "${NS_SERVER}" ip -d link show type ovpn 2>/dev/null | grep -q .; then
        fail "an ovpn-type netdev exists despite --disable-dco" "${SERVER_LOG}" /dev/null
    fi
fi

# Forwarding on the tun device is the server's own job (NetPolicy enables
# net.ipv4.conf.<dev>.forwarding on attach). Deliberately not set here: the
# allow case only passes if the server actually did it.

# ── Clients ──────────────────────────────────────────────────────────

echo "[3/5] Connecting both clients..."
declare -a TUN_IPS=()
for i in 0 1; do
    ns="$(mc_ns_client "${PREFIX}" "${i}")"
    cfg="${LOG_DIR}/client${i}.ovpn"
    log="${LOG_DIR}/client${i}.log"
    write_client_profile "${cfg}" "${SSL_DIR}" "${SERVER_IP}" "${PORT}"
    ns_bg "${ns}" "${CLI_BIN}" "${cfg}" >"${log}" 2>&1 &
    CLIENT_PIDS+=($!)
done
for i in 0 1; do
    ns="$(mc_ns_client "${PREFIX}" "${i}")"
    log="${LOG_DIR}/client${i}.log"
    if ! wait_for_connected "${log}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PIDS[$i]}"; then
        fail "Client ${i} did not connect within ${HANDSHAKE_TIMEOUT}s" "${SERVER_LOG}" "${log}"
    fi
    TUN_IPS[$i]="$(client_tun_ip "${ns}")"
    [[ -n "${TUN_IPS[$i]}" ]] || fail "Client ${i} has no tunnel address" "${SERVER_LOG}" "${log}"
    echo "      client-${i} connected as ${TUN_IPS[$i]}"
done

if [[ "${TUN_IPS[0]}" == "${TUN_IPS[1]}" ]]; then
    fail "Both clients were assigned ${TUN_IPS[0]} -- the pool handed out a duplicate" \
        "${SERVER_LOG}" "${LOG_DIR}/client0.log"
fi

# ── Baseline: the server itself must be reachable either way ─────────

echo "[4/5] Baseline -- both clients must reach the server at ${GATEWAY}..."
for i in 0 1; do
    ns="$(mc_ns_client "${PREFIX}" "${i}")"
    if ! ping_through_tunnel "${ns}" "${GATEWAY}" 2 3 "${LOG_DIR}/ping-gw-${i}.log"; then
        cat "${LOG_DIR}/ping-gw-${i}.log" || true
        fail "client-${i} cannot reach the server's own tunnel address" \
            "${SERVER_LOG}" "${LOG_DIR}/client${i}.log"
    fi
done
echo "      both clients reach the gateway"

# ── The scenario itself ──────────────────────────────────────────────

echo "[5/5] Scenario: ${MODE}"
case "${MODE}" in
deny | deny-dco)
    if ping_through_tunnel "${NS_C0}" "${TUN_IPS[1]}" 2 3 "${LOG_DIR}/ping-c2c.log"; then
        cat "${LOG_DIR}/ping-c2c.log" || true
        fail "client-0 reached client-1 at ${TUN_IPS[1]} with client_to_client off" \
            "${SERVER_LOG}" "${LOG_DIR}/client0.log"
    fi
    echo "      client-0 -> client-1 blocked, as required"
    ;;

allow | allow-dco)
    if ! ping_through_tunnel "${NS_C0}" "${TUN_IPS[1]}" 3 3 "${LOG_DIR}/ping-c2c.log"; then
        cat "${LOG_DIR}/ping-c2c.log" || true
        fail "client-0 could not reach client-1 at ${TUN_IPS[1]} with --client-to-client" \
            "${SERVER_LOG}" "${LOG_DIR}/client0.log"
    fi
    echo "      client-0 -> client-1 forwarded, as required"
    ;;

spoof | spoof-allow)
    SERVER_TUN="$(ns_exec "${NS_SERVER}" ip -o -4 addr show | awk -v gw="${GATEWAY}" '$4 ~ "^"gw"/" {print $2; exit}')"
    [[ -n "${SERVER_TUN}" ]] || fail "could not find the server's tun device (expected ${GATEWAY} on it)" \
        "${SERVER_LOG}" /dev/null
    echo "      server tun device: ${SERVER_TUN}"

    # Give client-0 an out-of-pool source it can legitimately bind, then send
    # from it. The server must not write a packet to its tun device when the
    # source is not the address it leased to that session.
    ns_exec "${NS_C0}" ip addr add "${SPOOFED_SRC}/32" dev tun
    ns_exec "${NS_SERVER}" tcpdump -n -i "${SERVER_TUN}" -c 1 "src ${SPOOFED_SRC}" \
        >"${LOG_DIR}/tcpdump-server.log" 2>&1 &
    TCPDUMP_PID=$!
    sleep 2

    ns_exec "${NS_C0}" ping -c 3 -W 2 -I "${SPOOFED_SRC}" "${TUN_IPS[1]}" \
        >"${LOG_DIR}/ping-spoof.log" 2>&1 || true

    sleep 3
    kill -TERM "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
    TCPDUMP_PID=""

    if grep -qE "IP ${SPOOFED_SRC}" "${LOG_DIR}/tcpdump-server.log"; then
        echo "--- tcpdump on the server's ${SERVER_TUN} ---"
        cat "${LOG_DIR}/tcpdump-server.log"
        fail "a packet sourced from ${SPOOFED_SRC} reached the server's tun device: the reverse-path check did not drop it" \
            "${SERVER_LOG}" "${LOG_DIR}/client0.log"
    fi
    echo "      nothing from ${SPOOFED_SRC} reached the server's tun, as required"

    if [[ "${MODE}" == "spoof-allow" ]]; then
        # ...and with c2c enabled the legitimate source still works, which is
        # what makes the result above attributable to the reverse-path check.
        if ! ping_through_tunnel "${NS_C0}" "${TUN_IPS[1]}" 3 3 "${LOG_DIR}/ping-legit.log"; then
            cat "${LOG_DIR}/ping-legit.log" || true
            fail "legitimate client-0 -> client-1 traffic also failed; the drop above proves nothing" \
                "${SERVER_LOG}" "${LOG_DIR}/client0.log"
        fi
        echo "      legitimate source still forwarded, so the drop was the RPF check"
    fi
    ;;
esac

echo ""
echo "=== PASSED (${MODE}) ==="
echo "    clients: ${TUN_IPS[0]} and ${TUN_IPS[1]}"
echo "    Logs: ${LOG_DIR}/"
