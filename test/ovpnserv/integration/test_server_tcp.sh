#!/bin/bash
# test_server_tcp.sh -- Server-side TCP transport integration test.
#
# Starts ovpnserv with --proto tcp in its own network namespace and a plain
# ovpncli in a second namespace, connected by a veth pair. Validates:
#   - the server accepts a TCP connection and completes a real handshake
#   - the server does NOT create a kernel "ovpn"-type netdev: DCO is a datagram
#     path and openvpn_server.hpp declines it outright on TCP, so a real tun
#     device must exist instead (see tcptransserv.hpp's header)
#   - ICMP passes end-to-end through the tunnel with 0% loss
#   - a client can disconnect and reconnect against the same server process,
#     which exercises connection teardown, re-accept, and address-pool release
#     (the TCP table is keyed by connection, so a reconnect is a new session)
#   - the tunnel is unreachable once the VPN is stopped
#
# This is the sibling of test_server_classic.sh: same shape, TCP transport
# instead of UDP. See lib.sh for the shared netns/handshake/ping helpers.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN (for the namespaces and the tun device)
#   - ovpnserv and ovpncli built (no special build option needed)
#
# Usage: sudo ./test_server_tcp.sh [BUILD_DIR]
#   BUILD_DIR defaults to out/build/linux-x64-release under the repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpncli"
SSL_DIR="${CORE_ROOT}/test/ssl"

NS_SERVER="ns-vpn-server-tcp"
NS_CLIENT="ns-vpn-client-tcp"
VETH_SERVER="veth-tcp-srv"
VETH_CLIENT="veth-tcp-cli"
SERVER_VETH_IP="192.168.96.1"
CLIENT_VETH_IP="192.168.96.2"
SERVER_PORT=11694

TUNNEL_SERVER_IP="10.8.0.1" # ovpnserv's default --gateway
HANDSHAKE_TIMEOUT="$(scaled 15)"
PING_COUNT=3
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-server-tcp-it"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
CLIENT_LOG2="${LOG_DIR}/client2.log"
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

echo "=== Server TCP transport integration test ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        echo "      run manually via: sudo ./test_server_tcp.sh"
        exit 77
    fi
fi

for bin in "${SERV_BIN}" "${CLI_BIN}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "SKIP: binary not found at ${bin}"
        echo "      Build ovpnserv and ovpncli first."
        exit 77
    fi
done
require_ping

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}" "${CLIENT_LOG2}"

netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

echo "[1/6] Starting ovpnserv --proto tcp in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${SERV_BIN}" \
    --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
    --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_VETH_IP}" --port "${SERVER_PORT}" --proto tcp \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
if ! grep -q "TCP server listening on" "${SERVER_LOG}"; then
    fail "Server did not report a TCP listener" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Server PID: ${SERVER_PID}, listening on TCP"

# DCO is declined on TCP by construction, so the classic tun path must be in use.
echo "[2/6] Verifying no kernel DCO netdev was created..."
if ns_exec "${NS_SERVER}" ip -d link show type ovpn 2>/dev/null | grep -q .; then
    fail "An ovpn-type netdev exists on a TCP server -- DCO must not engage over TCP" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Server: no ovpn-type netdev, as expected"

echo "[3/6] Starting ovpncli in ${NS_CLIENT}..."
# Written out here rather than via lib.sh's write_client_profile, which hardcodes
# "proto udp4".
cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto tcp4
remote ${SERVER_VETH_IP} ${SERVER_PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 4
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/client.crt
key ${SSL_DIR}/client.key
EOF

ns_bg "${NS_CLIENT}" "${CLI_BIN}" "${CLIENT_CFG}" \
    >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!

echo "[4/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."
if ! wait_for_connected "${CLIENT_LOG}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
    fail "Client did not complete handshake within ${HANDSHAKE_TIMEOUT}s (or a process died)" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
if ! grep -q "via /TCPv4" "${CLIENT_LOG}"; then
    fail "Client connected over something other than TCP" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
TUN_IP="$(client_tun_ip "${NS_CLIENT}")"
if [[ -z "${TUN_IP}" ]]; then
    fail "Client has no tunnel IP address" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Client connected over TCP, tunnel address ${TUN_IP}"

echo "[5/6] Pinging server (${TUNNEL_SERVER_IP}) through the tunnel..."
if ping_through_tunnel "${NS_CLIENT}" "${TUNNEL_SERVER_IP}" "${PING_COUNT}" "${PING_TIMEOUT}" \
    "${LOG_DIR}/ping.log"; then
    echo "      Ping OK, 0% loss"
else
    cat "${LOG_DIR}/ping.log" 2>/dev/null || true
    fail "Ping through the tunnel failed" "${SERVER_LOG}" "${CLIENT_LOG}"
fi

# A reconnect is a fresh connection and therefore a fresh session: this catches a
# connection whose teardown leaked its pool address or left the accept loop dead.
echo "[6/6] Reconnecting against the same server..."
kill -TERM "${CLIENT_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
CLIENT_PID=""

ns_bg "${NS_CLIENT}" "${CLI_BIN}" "${CLIENT_CFG}" \
    >"${CLIENT_LOG2}" 2>&1 &
CLIENT_PID=$!
if ! wait_for_connected "${CLIENT_LOG2}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
    fail "Client did not reconnect within ${HANDSHAKE_TIMEOUT}s" \
        "${SERVER_LOG}" "${CLIENT_LOG2}"
fi
if ! ping_through_tunnel "${NS_CLIENT}" "${TUNNEL_SERVER_IP}" "${PING_COUNT}" "${PING_TIMEOUT}" \
    "${LOG_DIR}/ping2.log"; then
    cat "${LOG_DIR}/ping2.log" 2>/dev/null || true
    fail "Ping after reconnect failed" "${SERVER_LOG}" "${CLIENT_LOG2}"
fi
echo "      Reconnected and passed traffic"

kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

if ! verify_unreachable "${NS_CLIENT}" "${TUNNEL_SERVER_IP}"; then
    fail "Tunnel still reachable after VPN stopped" "${SERVER_LOG}" "${CLIENT_LOG2}"
fi

echo ""
echo "=== PASSED ==="
echo "    Server: userspace TCP transport (TunReal, no kernel DCO)"
echo "    Client tunnel address: ${TUN_IP}"
echo "    Logs: ${LOG_DIR}/"
