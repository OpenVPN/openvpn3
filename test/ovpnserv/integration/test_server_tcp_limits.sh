#!/bin/bash
# test_server_tcp_limits.sh -- accept-side defenses of the TCP transport server.
#
# The happy path lives in test_server_tcp.sh. This covers what a TCP listener has
# instead of the UDP server's stateless psid cookie: a TCP peer has already
# proven return-path reachability by completing the handshake, so the defenses
# that matter are against a peer that then stalls, connects in bulk, sends
# rubbish, or stops reading. See tcptransserv.hpp's header.
#
# One scenario per invocation, so each is its own ctest entry and a failure names
# the case. Every mode drives the server with raw sockets rather than ovpncli,
# because the point is what happens to a client that never becomes one:
#
#   timeout      A connection that completes the TCP handshake and then sends
#                nothing must be closed once --handshake-timeout elapses.
#                Asserted by the peer observing EOF, not by reading the log, so
#                a server that merely logs without closing still fails.
#   prevalidate  With --tls-auth, a first packet that fails the HMAC gate must
#                cost the peer its connection and allocate no session.
#   per-addr     Concurrent connections beyond --max-conns-per-addr from one
#                source address must be refused.
#   max-clients  Connections beyond --max-clients must be refused, counted
#                before a session exists (an unauthenticated connection still
#                occupies a table slot).
#   overflow     A peer that completes a real handshake and then stops reading
#                must have its connection dropped once more than
#                --send-queue-max-packets packets are queued for it, rather
#                than growing the server's memory on its behalf.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN (namespaces, tun device)
#   - ovpnserv built; python3 for the raw-socket probes
#   - the overflow mode additionally needs ovpncli and ping
#
# Usage: sudo ./test_server_tcp_limits.sh [BUILD_DIR] [MODE]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"
MODE="${2:-timeout}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpncli"
SSL_DIR="${CORE_ROOT}/test/ssl"

# Namespace and link names derive from the mode so the scenarios run in
# parallel under ctest. Kept short: link names are IFNAMSIZ-bound.
case "${MODE}" in
timeout) SUFFIX=tmo PORT=11894 ;;
prevalidate) SUFFIX=pv PORT=11895 ;;
per-addr) SUFFIX=pa PORT=11896 ;;
max-clients) SUFFIX=mc PORT=11897 ;;
overflow) SUFFIX=ovf PORT=11898 ;;
*)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

NS_SERVER="ns-tcplim-${SUFFIX}-s"
NS_CLIENT="ns-tcplim-${SUFFIX}-c"
VETH_SERVER="vtl${SUFFIX}s"
VETH_CLIENT="vtl${SUFFIX}c"
SERVER_VETH_IP="192.168.95.1"
CLIENT_VETH_IP="192.168.95.2"
TUNNEL_SERVER_IP="10.8.0.1"

LOG_DIR="/tmp/vpn-server-tcp-limits-${MODE}"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
CLIENT_CFG="${LOG_DIR}/client.ovpn"

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "${CLIENT_PID}" ]] && kill -CONT "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${CLIENT_PID}" ]] && kill -9 "${CLIENT_PID}" 2>/dev/null || true
    [[ -n "${SERVER_PID}" ]] && kill -TERM "${SERVER_PID}" 2>/dev/null || true
    sleep 1
    [[ -n "${SERVER_PID}" ]] && kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    netns_teardown "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}"
}
trap cleanup EXIT

echo "=== Server TCP accept-side defenses -- mode: ${MODE} ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        exit 77
    fi
fi

if [[ ! -x "${SERV_BIN}" ]]; then
    echo "SKIP: binary not found at ${SERV_BIN}"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 required for the raw-socket probes"
    exit 77
fi
if [[ "${MODE}" == "overflow" ]]; then
    [[ -x "${CLI_BIN}" ]] || { echo "SKIP: ovpncli not found at ${CLI_BIN}"; exit 77; }
    require_ping
fi

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

# ── Raw-socket probes ────────────────────────────────────────────────
#
# Run in the client namespace. Kept in python3 rather than bash's /dev/tcp
# because these need per-socket read timeouts and several concurrent
# connections held open at once.

# Open one connection, optionally send hex bytes, then report whether the
# server closes it within TIMEOUT seconds.
# Usage: probe_one HOST PORT TIMEOUT [HEXBYTES]  -> prints EOF | OPEN | DATA
probe_one() {
    ns_exec "${NS_CLIENT}" python3 -c '
import binascii, socket, sys
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
payload = sys.argv[4] if len(sys.argv) > 4 else ""
s = socket.create_connection((host, port), timeout=5)
if payload:
    s.sendall(binascii.unhexlify(payload))
s.settimeout(timeout)
try:
    print("EOF" if not s.recv(1) else "DATA")
except socket.timeout:
    print("OPEN")
except OSError:
    print("EOF")
finally:
    s.close()
' "$1" "$2" "$3" ${4:+"$4"}
}

# Open N connections at once, hold them, then report how many the server closed.
# Usage: probe_many HOST PORT N WAIT  -> prints "opened=<n> closed=<n>"
probe_many() {
    ns_exec "${NS_CLIENT}" python3 -c '
import socket, sys, time
host, port, n, wait = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
conns, refused = [], 0
for _ in range(n):
    try:
        conns.append(socket.create_connection((host, port), timeout=5))
    except OSError:
        refused += 1
time.sleep(wait)
closed = refused
for s in conns:
    s.settimeout(0.5)
    try:
        if not s.recv(1):
            closed += 1
    except socket.timeout:
        pass
    except OSError:
        closed += 1
print(f"opened={len(conns)} closed={closed}")
for s in conns:
    s.close()
' "$1" "$2" "$3" "$4"
}

# Usage: start_server EXTRA_ARGS...
start_server() {
    ns_bg "${NS_SERVER}" "${SERV_BIN}" \
        --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
        --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_VETH_IP}" --port "${PORT}" --proto tcp \
        "$@" >"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server exited immediately" "${SERVER_LOG}" /dev/null
    fi
    if ! grep -q "TCP server listening on" "${SERVER_LOG}"; then
        fail "Server did not report a TCP listener" "${SERVER_LOG}" /dev/null
    fi
}

case "${MODE}" in

timeout)
    echo "[1/2] Starting server with --handshake-timeout 2..."
    start_server --handshake-timeout 2
    echo "[2/2] Opening a connection that sends nothing..."
    # Allow the 2s timeout plus scheduling slack.
    RESULT="$(probe_one "${SERVER_VETH_IP}" "${PORT}" "$(scaled 8)")"
    echo "      probe result: ${RESULT}"
    if [[ "${RESULT}" != "EOF" ]]; then
        fail "A silent connection was not closed after the handshake timeout (${RESULT})" \
            "${SERVER_LOG}" /dev/null
    fi
    grep -q "handshake timeout" "${SERVER_LOG}" \
        || fail "Server closed the connection but logged no handshake timeout" \
            "${SERVER_LOG}" /dev/null
    echo "      silent connection closed by the server, as required"
    ;;

prevalidate)
    echo "[1/2] Starting server with --tls-auth (enables the HMAC gate)..."
    start_server --tls-auth "${SSL_DIR}/tls-auth.key" --handshake-timeout 30
    echo "[2/2] Sending a framed but bogus first packet..."
    # 16-bit length prefix (0x0010) then 16 bytes that cannot HMAC-verify. The
    # opcode nibble is a plausible HARD_RESET_CLIENT_V2 (7 << 3) so the packet
    # reaches the prevalidator rather than being discarded on shape alone.
    RESULT="$(probe_one "${SERVER_VETH_IP}" "${PORT}" "$(scaled 8)" \
        "0010380102030405060708090a0b0c0d0e0f")"
    echo "      probe result: ${RESULT}"
    if [[ "${RESULT}" != "EOF" ]]; then
        fail "A connection whose first packet failed prevalidation stayed open (${RESULT})" \
            "${SERVER_LOG}" /dev/null
    fi
    grep -q "failed prevalidation" "${SERVER_LOG}" \
        || fail "Server dropped the connection but logged no prevalidation failure" \
            "${SERVER_LOG}" /dev/null
    echo "      bogus first packet cost the peer its connection, as required"
    ;;

per-addr)
    echo "[1/2] Starting server with --max-conns-per-addr 2..."
    start_server --max-conns-per-addr 2 --handshake-timeout 30
    echo "[2/2] Opening 4 concurrent connections from one address..."
    RESULT="$(probe_many "${SERVER_VETH_IP}" "${PORT}" 4 "$(scaled 3)")"
    echo "      ${RESULT}"
    CLOSED="${RESULT##*closed=}"
    if ((CLOSED < 2)); then
        fail "Expected at least 2 of 4 connections refused past the per-address limit, got ${CLOSED}" \
            "${SERVER_LOG}" /dev/null
    fi
    grep -q "per-address connection limit reached" "${SERVER_LOG}" \
        || fail "Server refused connections but logged no per-address limit" \
            "${SERVER_LOG}" /dev/null
    echo "      per-address limit enforced, as required"
    ;;

max-clients)
    echo "[1/2] Starting server with --max-clients 1..."
    start_server --max-clients 1 --max-conns-per-addr 0 --handshake-timeout 30
    echo "[2/2] Opening 3 concurrent connections..."
    RESULT="$(probe_many "${SERVER_VETH_IP}" "${PORT}" 3 "$(scaled 3)")"
    echo "      ${RESULT}"
    CLOSED="${RESULT##*closed=}"
    if ((CLOSED < 2)); then
        fail "Expected at least 2 of 3 connections refused past max_clients, got ${CLOSED}" \
            "${SERVER_LOG}" /dev/null
    fi
    grep -q "max_clients reached" "${SERVER_LOG}" \
        || fail "Server refused connections but logged no max_clients message" \
            "${SERVER_LOG}" /dev/null
    echo "      max_clients enforced before a session exists, as required"
    ;;

overflow)
    echo "[1/4] Starting server with a small --send-queue-max-packets..."
    start_server --send-queue-max-packets 8 --handshake-timeout 30

    echo "[2/4] Connecting a real client..."
    cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto tcp4
remote ${SERVER_VETH_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/client.crt
key ${SSL_DIR}/client.key
EOF
    ns_bg "${NS_CLIENT}" "${CLI_BIN}" "${CLIENT_CFG}" >"${CLIENT_LOG}" 2>&1 &
    CLIENT_PID=$!
    if ! wait_for_connected "${CLIENT_LOG}" "$(scaled 15)" "${SERVER_PID}" "${CLIENT_PID}"; then
        fail "Client did not connect" "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    TUN_IP="$(client_tun_ip "${NS_CLIENT}")"
    [[ -n "${TUN_IP}" ]] || fail "Client has no tunnel address" "${SERVER_LOG}" "${CLIENT_LOG}"
    echo "      Client connected as ${TUN_IP}"

    # SIGSTOP leaves the socket open with nobody draining it, which is the
    # condition the send queue exists to bound. Killing the client instead would
    # close the socket and exercise nothing.
    echo "[3/4] Stopping the client so it stops reading, then flooding it..."
    kill -STOP "${CLIENT_PID}"
    sleep 1
    ns_exec "${NS_SERVER}" ping -f -s 1400 -c 4000 -W 1 "${TUN_IP}" \
        >"${LOG_DIR}/flood.log" 2>&1 || true
    sleep 2

    echo "[4/4] Checking the server dropped the connection..."
    if ! grep -qE "TCP_OVERFLOW|TCP server: .*overflow" "${SERVER_LOG}"; then
        echo "--- server log tail ---"
        tail -20 "${SERVER_LOG}" || true
        fail "Server did not report a send-queue overflow for a client that stopped reading" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    kill -CONT "${CLIENT_PID}" 2>/dev/null || true
    echo "      send-queue overflow dropped the connection, as required"
    ;;
esac

echo ""
echo "=== PASSED (${MODE}) ==="
echo "    Logs: ${LOG_DIR}/"
