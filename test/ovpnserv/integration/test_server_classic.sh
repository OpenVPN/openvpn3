#!/bin/bash
# test_server_classic.sh — Server-side classic (non-DCO) userspace UDP
# integration test.
#
# Starts ovpnserv with --disable-dco (forcing the userspace TunReal data path
# even though kernel DCO would otherwise be attempted opportunistically) in
# its own network namespace, and a plain ovpncli in a second namespace,
# connected by a veth pair. Validates:
#   - the server does NOT create a kernel "ovpn"-type netdev (proving DCO was
#     actually declined, not silently unavailable) -- a real tun device
#     exists instead
#   - the client completes a handshake against it
#   - ICMP passes end-to-end through the tunnel with 0% loss
#   - the tunnel is unreachable once the VPN is stopped
#
# This is the sibling of test_server_dco.sh: same shape (see lib.sh for the
# shared netns/handshake/ping helpers), opposite netdev-type assertion, no
# kernel-module prerequisite.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN (for the namespaces and the tun device)
#   - ovpnserv and ovpncli built (no special build option needed)
#
# Usage: sudo ./test_server_classic.sh [BUILD_DIR]
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

NS_SERVER="ns-vpn-server-classic"
NS_CLIENT="ns-vpn-client-classic"
VETH_SERVER="veth-cls-srv"
VETH_CLIENT="veth-cls-cli"
SERVER_VETH_IP="192.168.90.1"
CLIENT_VETH_IP="192.168.90.2"
SERVER_PORT=11394

TUNNEL_SERVER_IP="10.8.0.1" # ovpnserv's default --gateway
HANDSHAKE_TIMEOUT="$(scaled 15)"
PING_COUNT=3
PING_TIMEOUT=3

LOG_DIR="/tmp/vpn-server-classic-it"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
CLIENT_CFG="${LOG_DIR}/client.ovpn"

SERVER_PID=""
CLIENT_PID=""

# ── Helpers ──────────────────────────────────────────────────────────

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

# ── Preconditions ────────────────────────────────────────────────────

echo "=== Server classic (non-DCO) integration test ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        echo "      run manually via: sudo ./test_server_classic.sh"
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
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

# ── Namespace + veth setup ───────────────────────────────────────────

netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

# ── Start server ─────────────────────────────────────────────────────

echo "[1/6] Starting classic (--disable-dco) ovpnserv in ${NS_SERVER}..."
ns_bg "${NS_SERVER}" "${SERV_BIN}" \
    --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
    --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_VETH_IP}" --port "${SERVER_PORT}" --disable-dco \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    fail "Server exited immediately" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Server PID: ${SERVER_PID}"

# ── Verify DCO did NOT engage ─────────────────────────────────────────

echo "[2/6] Verifying no kernel DCO netdev was created..."
if ns_exec "${NS_SERVER}" ip -d link show type ovpn 2>/dev/null | grep -q .; then
    fail "An ovpn-type netdev exists despite --disable-dco -- DCO engaged anyway" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Server: no ovpn-type netdev, as expected"

# ── Start client ──────────────────────────────────────────────────────

echo "[3/6] Starting ovpncli in ${NS_CLIENT}..."
cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto udp4
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

# ── Wait for handshake ────────────────────────────────────────────────

echo "[4/6] Waiting up to ${HANDSHAKE_TIMEOUT}s for handshake..."
if ! wait_for_connected "${CLIENT_LOG}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
    fail "Client did not complete handshake within ${HANDSHAKE_TIMEOUT}s (or a process died)" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Client connected"

TUN_IP=$(ns_exec "${NS_CLIENT}" ip -4 addr show dev tun 2>/dev/null | grep -oP 'inet \K[0-9.]+' || echo "")
if [[ -z "${TUN_IP}" ]]; then
    fail "Client has no tunnel IP address" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Client tunnel address: ${TUN_IP}"

# ── Ping through the tunnel ───────────────────────────────────────────

echo "[5/6] Pinging server (${TUNNEL_SERVER_IP}) through the tunnel..."
if ping_through_tunnel "${NS_CLIENT}" "${TUNNEL_SERVER_IP}" "${PING_COUNT}" "${PING_TIMEOUT}" "${LOG_DIR}/ping.log"; then
    echo "      Ping OK, 0% loss"
else
    cat "${LOG_DIR}/ping.log" 2>/dev/null || true
    fail "Ping through the tunnel failed" "${SERVER_LOG}" "${CLIENT_LOG}"
fi

# ── Negative validation ───────────────────────────────────────────────

echo "[6/6] Stopping VPN, confirming tunnel dies..."
kill -TERM "${CLIENT_PID}" 2>/dev/null || true
kill -TERM "${SERVER_PID}" 2>/dev/null || true
sleep 2
kill -9 "${CLIENT_PID}" 2>/dev/null || true
kill -9 "${SERVER_PID}" 2>/dev/null || true
wait 2>/dev/null || true
CLIENT_PID=""
SERVER_PID=""

if ! verify_unreachable "${NS_CLIENT}" "${TUNNEL_SERVER_IP}"; then
    fail "Tunnel still reachable after VPN stopped" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Tunnel correctly unreachable after VPN stopped"

echo ""
echo "=== PASSED ==="
echo "    Server: classic userspace UDP datapath (TunReal, no kernel DCO)"
echo "    Client tunnel address: ${TUN_IP}"
echo "    Logs: ${LOG_DIR}/"
