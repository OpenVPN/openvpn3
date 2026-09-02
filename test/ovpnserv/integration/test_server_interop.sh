#!/bin/bash
# test_server_interop.sh -- interoperability against reference OpenVPN 2.
#
# Every other integration test in this directory is us against us: our ovpnserv
# against our ovpncli. Those prove the engine is self-consistent, not that it
# speaks the protocol. These run the reference `openvpn` binary on the other end
# of the wire, in both directions:
#
#   ref-client-udp    reference 2.x client  -> our ovpnserv, UDP
#   ref-client-tcp    reference 2.x client  -> our ovpnserv, TCP
#   ref-server-udp    our ovpncli           -> reference 2.x server, UDP
#   ref-server-tcp    our ovpncli           -> reference 2.x server, TCP
#   tls-crypt-v2      reference 2.x client  -> our ovpnserv, WKc handshake
#   ncp               reference 2.x client offering a cipher list that contains
#                     the server's single cipher; the pushed cipher must be
#                     accepted and traffic must flow
#   ncp-mismatch      reference 2.x client offering no cipher the server has.
#                     The server must refuse at auth with OpenVPN 2's own
#                     message rather than pushing an unusable cipher, and must
#                     allocate no pool address doing so.
#
# Both products are OpenVPN's own, which is exactly why this matters: nothing
# about a shared vendor makes two independent implementations of the same wire
# protocol agree, and the O3 server has no other check that it does.
#
# The reference binary's version is recorded in the output rather than pinned:
# RFC §5.7's interop section was written against 2.6, hosts now ship 2.7, and a
# test that silently tests a different version than it claims is worse than one
# that says which it used.
#
# The server still negotiates nothing -- it has one cipher and pushes it. What
# it now does, matching v2, is read the peer's announced list and refuse up
# front when its cipher is absent, instead of pushing something the peer cannot
# use and leaving it to retry. ncp-mismatch is that behaviour.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN (namespaces, tun devices)
#   - ovpnserv, ovpncli, ping, and a reference `openvpn` binary on PATH
#     (or at $OPENVPN_REF)
#
# Usage: sudo ./test_server_interop.sh [BUILD_DIR] [MODE]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"
MODE="${2:-ref-client-udp}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpncli"
SSL_DIR="${CORE_ROOT}/test/ssl"
REF_BIN="${OPENVPN_REF:-/usr/sbin/openvpn}"

# Namespace and link names derive from the mode so scenarios run in parallel
# under ctest. Kept short: link names are IFNAMSIZ-bound.
case "${MODE}" in
ref-client-udp) SUFFIX=rcu PORT=12094 PROTO=udp ;;
ref-client-tcp) SUFFIX=rct PORT=12095 PROTO=tcp ;;
ref-server-udp) SUFFIX=rsu PORT=12096 PROTO=udp ;;
ref-server-tcp) SUFFIX=rst PORT=12097 PROTO=tcp ;;
tls-crypt-v2) SUFFIX=tc2 PORT=12098 PROTO=udp ;;
ncp) SUFFIX=ncp PORT=12099 PROTO=udp ;;
ncp-mismatch) SUFFIX=ncpx PORT=12100 PROTO=udp ;;
*)
    echo "unknown mode: ${MODE}" >&2
    exit 2
    ;;
esac

NS_SERVER="ns-iop-${SUFFIX}-s"
NS_CLIENT="ns-iop-${SUFFIX}-c"
VETH_SERVER="vio${SUFFIX}s"
VETH_CLIENT="vio${SUFFIX}c"
SERVER_VETH_IP="192.168.89.1"
CLIENT_VETH_IP="192.168.89.2"

# Our server's default gateway; the reference server is told to use a different
# subnet so a stale route from one mode cannot mask a failure in another.
OUR_TUNNEL_IP="10.8.0.1"
REF_TUNNEL_IP="10.9.0.1"

HANDSHAKE_TIMEOUT="$(scaled 25)"
LOG_DIR="/tmp/vpn-server-interop-${MODE}"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
# .ovpn, not .conf: ovpncli rejects a profile without that extension
# (ERR_PROFILE_NO_OVPN_EXTENSION), while the reference binary's --config takes
# any name, so one suffix serves both ends.
CLIENT_CFG="${LOG_DIR}/client.ovpn"
SERVER_CFG="${LOG_DIR}/server.conf"

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

echo "=== O3 server interop vs reference OpenVPN 2 -- mode: ${MODE} ==="

if [[ $(id -u) -ne 0 ]]; then
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH,OPENVPN_REF "$0" "$@"
    else
        echo "SKIP: root required and passwordless sudo not available"
        exit 77
    fi
fi

if [[ ! -x "${REF_BIN}" ]]; then
    echo "SKIP: reference openvpn not found at ${REF_BIN}"
    echo "      set OPENVPN_REF to its path"
    exit 77
fi
for bin in "${SERV_BIN}" "${CLI_BIN}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "SKIP: binary not found at ${bin}"
        exit 77
    fi
done
require_ping

REF_VERSION="$("${REF_BIN}" --version 2>&1 | head -1 || true)"
echo "      reference: ${REF_VERSION}"

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

# ── Helpers ──────────────────────────────────────────────────────────

# Start our ovpnserv. Usage: start_our_server EXTRA_ARGS...
start_our_server() {
    local proto_arg=()
    [[ "${PROTO}" == tcp ]] && proto_arg=(--proto tcp)
    ns_bg "${NS_SERVER}" "${SERV_BIN}" \
        --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
        --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_VETH_IP}" --port "${PORT}" \
        --disable-dco "${proto_arg[@]}" "$@" >"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!
    sleep 2
    kill -0 "${SERVER_PID}" 2>/dev/null \
        || fail "Our server exited immediately" "${SERVER_LOG}" /dev/null
}

# Write a reference-client config. Usage: write_ref_client_config [EXTRA_LINE...]
write_ref_client_config() {
    cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto ${PROTO}
remote ${SERVER_VETH_IP} ${PORT}
nobind
remote-cert-tls server
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/client.crt
key ${SSL_DIR}/client.key
verb 4
EOF
    local line
    for line in "$@"; do
        echo "${line}" >>"${CLIENT_CFG}"
    done
}

# Wait for the reference binary to report a completed startup.
# Usage: wait_for_ref_init LOGFILE TIMEOUT WATCH_PID...
wait_for_ref_init() {
    local log="$1" timeout="$2"
    shift 2
    local i pid
    for ((i = 0; i < timeout; i++)); do
        grep -q "Initialization Sequence Completed" "${log}" 2>/dev/null && return 0
        for pid in "$@"; do
            kill -0 "${pid}" 2>/dev/null || return 1
        done
        sleep 1
    done
    return 1
}

# ── Scenarios ────────────────────────────────────────────────────────

case "${MODE}" in

ref-client-udp | ref-client-tcp | tls-crypt-v2 | ncp)
    # Reference client against our server.
    SRV_EXTRA=()
    CLI_EXTRA=("data-ciphers AES-256-GCM")
    case "${MODE}" in
    tls-crypt-v2)
        SRV_EXTRA=(--tls-crypt-v2 "${SSL_DIR}/tls-crypt-v2-server.key")
        CLI_EXTRA+=("tls-crypt-v2 ${SSL_DIR}/tls-crypt-v2-client.key")
        ;;
    ncp)
        # Our server has no negotiable list: it pushes its single cipher. A
        # reference client offering several, ours not first, must accept the
        # pushed one.
        CLI_EXTRA=("data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305")
        ;;
    esac

    echo "[1/3] Starting our ovpnserv (${PROTO})..."
    start_our_server "${SRV_EXTRA[@]}"

    echo "[2/3] Connecting the reference client..."
    write_ref_client_config "${CLI_EXTRA[@]}"
    ns_bg "${NS_CLIENT}" "${REF_BIN}" --config "${CLIENT_CFG}" --disable-dco \
        >"${CLIENT_LOG}" 2>&1 &
    CLIENT_PID=$!
    if ! wait_for_ref_init "${CLIENT_LOG}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
        fail "Reference client did not complete startup against our server" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    # Our server must have seen it as a real client, not merely accepted bytes.
    grep -q "client connected" "${SERVER_LOG}" \
        || fail "Our server never reported a connected client" "${SERVER_LOG}" "${CLIENT_LOG}"
    echo "      Reference client connected"

    echo "[3/3] Pinging our server (${OUR_TUNNEL_IP}) through the tunnel..."
    if ! ping_through_tunnel "${NS_CLIENT}" "${OUR_TUNNEL_IP}" 3 3 "${LOG_DIR}/ping.log"; then
        cat "${LOG_DIR}/ping.log" 2>/dev/null || true
        fail "No traffic through the tunnel" "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    echo "      Traffic OK, 0% loss"
    ;;

ncp-mismatch)
    echo "[1/3] Starting our ovpnserv (cipher AES-256-GCM)..."
    start_our_server

    echo "[2/3] Connecting a reference client that offers no cipher we have..."
    write_ref_client_config "data-ciphers CHACHA20-POLY1305"
    ns_bg "${NS_CLIENT}" "${REF_BIN}" --config "${CLIENT_CFG}" --disable-dco \
        >"${CLIENT_LOG}" 2>&1 &
    CLIENT_PID=$!

    # The refusal is terminal, so waiting for the message beats waiting for a
    # connection that must never happen.
    for ((i = 0; i < $(scaled 20); i++)); do
        grep -q "AUTH_FAILED" "${CLIENT_LOG}" 2>/dev/null && break
        sleep 1
    done

    echo "[3/3] Checking the client was told why, and that nothing was allocated..."
    grep -q "AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)" \
        "${CLIENT_LOG}" \
        || fail "Client did not receive OpenVPN 2's cipher-negotiation failure message" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    # A push would mean the server tried to seat the client instead of refusing.
    if grep -q "PUSH_REPLY" "${SERVER_LOG}"; then
        fail "Server pushed a config to a client whose cipher list excludes its cipher" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    grep -q "no common cipher between server and client" "${SERVER_LOG}" \
        || fail "Server logged no diagnostic naming both cipher lists" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    echo "      refused with v2's message, no address allocated"
    ;;

ref-server-udp | ref-server-tcp)
    # Our client against a reference server.
    echo "[1/3] Starting the reference server (${PROTO})..."
    cat >"${SERVER_CFG}" <<EOF
mode server
tls-server
dev tun
proto ${PROTO}
local ${SERVER_VETH_IP}
port ${PORT}
server 10.9.0.0 255.255.255.0
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/server.crt
key ${SSL_DIR}/server.key
dh ${SSL_DIR}/dh.pem
data-ciphers AES-256-GCM
keepalive 10 60
verb 4
EOF
    ns_bg "${NS_SERVER}" "${REF_BIN}" --config "${SERVER_CFG}" --disable-dco \
        >"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!
    if ! wait_for_ref_init "${SERVER_LOG}" "$(scaled 15)" "${SERVER_PID}"; then
        fail "Reference server did not start" "${SERVER_LOG}" /dev/null
    fi
    echo "      Reference server up"

    echo "[2/3] Connecting our ovpncli..."
    cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto ${PROTO}4
remote ${SERVER_VETH_IP} ${PORT}
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
    ns_bg "${NS_CLIENT}" "${CLI_BIN}" "${CLIENT_CFG}" >"${CLIENT_LOG}" 2>&1 &
    CLIENT_PID=$!
    if ! wait_for_connected "${CLIENT_LOG}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
        fail "Our client did not connect to the reference server" \
            "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    TUN_IP="$(client_tun_ip "${NS_CLIENT}")"
    [[ -n "${TUN_IP}" ]] \
        || fail "Our client has no tunnel address" "${SERVER_LOG}" "${CLIENT_LOG}"
    echo "      Our client connected as ${TUN_IP}"

    echo "[3/3] Pinging the reference server (${REF_TUNNEL_IP}) through the tunnel..."
    if ! ping_through_tunnel "${NS_CLIENT}" "${REF_TUNNEL_IP}" 3 3 "${LOG_DIR}/ping.log"; then
        cat "${LOG_DIR}/ping.log" 2>/dev/null || true
        fail "No traffic through the tunnel" "${SERVER_LOG}" "${CLIENT_LOG}"
    fi
    echo "      Traffic OK, 0% loss"
    ;;
esac

echo ""
echo "=== PASSED (${MODE}) ==="
echo "    reference: ${REF_VERSION}"
echo "    Logs: ${LOG_DIR}/"
