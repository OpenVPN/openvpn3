#!/bin/bash
# test_server_config.sh -- the reference server driven entirely by a config file.
#
# test_servconf.cpp unit-tests the directive-to-Config mapping with inline PKI
# and never touches disk. This covers what those cannot:
#
#   run       A complete OpenVPN 2-style server.conf using `ca <path>` file
#             references brings up a working server, and a *reference* openvpn
#             client connects to it and passes traffic. Also asserts the derived
#             tunnel addressing: the pool comes from `server <net> <mask>`, not
#             from ovpnserv's argv defaults, so a config file that silently
#             failed to apply would be caught rather than looking like a pass.
#   refuse    The binary exits non-zero, with the directive named, on a config
#             carrying a directive it cannot honour. Asserted at the process
#             level because that is the contract an operator relies on: a
#             server that cannot do what its config says must not start.
#
# Prerequisites:
#   - Root / CAP_NET_ADMIN (namespaces, tun device) for the `run` mode
#   - ovpnserv built; the `run` mode also needs a reference `openvpn` and ping
#
# Usage: sudo ./test_server_config.sh [BUILD_DIR] [run|refuse]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"
MODE="${2:-run}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
SSL_DIR="${CORE_ROOT}/test/ssl"
REF_BIN="${OPENVPN_REF:-/usr/sbin/openvpn}"

NS_SERVER="ns-cfg-s"
NS_CLIENT="ns-cfg-c"
VETH_SERVER="vcfgs"
VETH_CLIENT="vcfgc"
SERVER_VETH_IP="192.168.86.1"
CLIENT_VETH_IP="192.168.86.2"
PORT=12394

# Deliberately not ovpnserv's 10.8.0.0/24 default: the point is to prove the
# file was applied.
CONF_NETWORK="10.44.0.0"
CONF_NETMASK="255.255.255.0"
CONF_GATEWAY="10.44.0.1"
CONF_FIRST_CLIENT="10.44.0.2"

# Scoped by effective uid: the "refuse" mode deliberately needs no privileges,
# so it must not collide with a directory a previous privileged run of this
# suite left behind owned by root.
LOG_DIR="/tmp/vpn-server-config-${MODE}-$(id -u)"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
SERVER_CONF="${LOG_DIR}/server.conf"
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

echo "=== ovpnserv --config -- mode: ${MODE} ==="

if [[ ! -x "${SERV_BIN}" ]]; then
    echo "SKIP: binary not found at ${SERV_BIN}"
    exit 77
fi

mkdir -p "${LOG_DIR}"

# ── refuse: no privileges or network needed ──────────────────────────

if [[ "${MODE}" == "refuse" ]]; then
    echo "[1/2] A config with an unhonourable directive must be rejected..."
    cat >"${SERVER_CONF}" <<EOF
mode server
dev tun
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/server.crt
key ${SSL_DIR}/server.key
server ${CONF_NETWORK} ${CONF_NETMASK}
duplicate-cn
EOF
    set +e
    OUTPUT="$("${SERV_BIN}" --config "${SERVER_CONF}" 2>&1)"
    STATUS=$?
    set -e
    if ((STATUS == 0)); then
        echo "${OUTPUT}"
        echo "FAIL: server started despite an unsupported directive"
        exit 1
    fi
    if ! grep -q "duplicate-cn" <<<"${OUTPUT}"; then
        echo "${OUTPUT}"
        echo "FAIL: rejection did not name the offending directive"
        exit 1
    fi
    echo "      rejected, naming 'duplicate-cn'"

    echo "[2/2] --config must not be silently combined with flags..."
    cat >"${SERVER_CONF}" <<EOF
mode server
dev tun
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/server.crt
key ${SSL_DIR}/server.key
server ${CONF_NETWORK} ${CONF_NETMASK}
EOF
    set +e
    OUTPUT="$("${SERV_BIN}" --config "${SERVER_CONF}" --port 9999 2>&1)"
    STATUS=$?
    set -e
    if ((STATUS == 0)); then
        echo "${OUTPUT}"
        echo "FAIL: server accepted --config together with --port"
        exit 1
    fi
    grep -q -- "--port" <<<"${OUTPUT}" \
        || { echo "${OUTPUT}"; echo "FAIL: conflict did not name --port"; exit 1; }
    echo "      rejected, naming the conflicting flag"

    echo ""
    echo "=== PASSED (${MODE}) ==="
    exit 0
fi

# ── run: needs root, a reference client, and ping ─────────────────────

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
    exit 77
fi
require_ping

rm -f "${SERVER_LOG}" "${CLIENT_LOG}"
netns_setup "${NS_SERVER}" "${NS_CLIENT}" "${VETH_SERVER}" "${VETH_CLIENT}" \
    "${SERVER_VETH_IP}" "${CLIENT_VETH_IP}"

echo "[1/4] Writing an OpenVPN 2-style server.conf (file-path PKI)..."
cat >"${SERVER_CONF}" <<EOF
# Deliberately in v2 idiom: mode/tls-server, file paths, server <net> <mask>.
mode server
tls-server
dev tun
proto udp
local ${SERVER_VETH_IP}
port ${PORT}
server ${CONF_NETWORK} ${CONF_NETMASK}
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/server.crt
key ${SSL_DIR}/server.key
dh ${SSL_DIR}/dh.pem
data-ciphers AES-256-GCM
keepalive 10 60
max-clients 32
disable-dco
persist-key
verb 3
EOF

echo "[2/4] Starting ovpnserv --config..."
ns_bg "${NS_SERVER}" "${SERV_BIN}" --config "${SERVER_CONF}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
sleep 2
kill -0 "${SERVER_PID}" 2>/dev/null \
    || fail "Server exited immediately" "${SERVER_LOG}" /dev/null

# The banner reports the effective config, so it is the check that the file
# actually took rather than the argv defaults.
grep -q "listening on ${SERVER_VETH_IP}:${PORT}" "${SERVER_LOG}" \
    || fail "Server did not report the configured listener" "${SERVER_LOG}" /dev/null
# Inert directives must be reported, not dropped in silence.
grep -q "accepted and ignored" "${SERVER_LOG}" \
    || fail "Server did not report the directives it ignored" "${SERVER_LOG}" /dev/null
echo "      Listening per the config file, ignored directives reported"

echo "[3/4] Connecting a reference client..."
cat >"${CLIENT_CFG}" <<EOF
client
dev tun
proto udp
remote ${SERVER_VETH_IP} ${PORT}
nobind
remote-cert-tls server
ca ${SSL_DIR}/ca.crt
cert ${SSL_DIR}/client.crt
key ${SSL_DIR}/client.key
data-ciphers AES-256-GCM
verb 3
EOF
ns_bg "${NS_CLIENT}" "${REF_BIN}" --config "${CLIENT_CFG}" --disable-dco \
    >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
for ((i = 0; i < $(scaled 25); i++)); do
    grep -q "Initialization Sequence Completed" "${CLIENT_LOG}" 2>/dev/null && break
    kill -0 "${SERVER_PID}" 2>/dev/null || fail "Server died" "${SERVER_LOG}" "${CLIENT_LOG}"
    sleep 1
done
grep -q "Initialization Sequence Completed" "${CLIENT_LOG}" \
    || fail "Reference client did not connect" "${SERVER_LOG}" "${CLIENT_LOG}"

# The addressing must come from `server <net> <mask>`, not ovpnserv's defaults.
if ! ns_exec "${NS_CLIENT}" ip -4 addr show | grep -q "${CONF_FIRST_CLIENT}"; then
    ns_exec "${NS_CLIENT}" ip -4 addr show || true
    fail "Client was not assigned ${CONF_FIRST_CLIENT} from 'server ${CONF_NETWORK} ${CONF_NETMASK}'" \
        "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Connected, assigned ${CONF_FIRST_CLIENT} as the config file dictates"

echo "[4/4] Pinging the derived gateway ${CONF_GATEWAY} through the tunnel..."
if ! ping_through_tunnel "${NS_CLIENT}" "${CONF_GATEWAY}" 3 3 "${LOG_DIR}/ping.log"; then
    cat "${LOG_DIR}/ping.log" 2>/dev/null || true
    fail "No traffic through the tunnel" "${SERVER_LOG}" "${CLIENT_LOG}"
fi
echo "      Traffic OK, 0% loss"

echo ""
echo "=== PASSED (${MODE}) ==="
echo "    Server configured entirely from ${SERVER_CONF}"
echo "    Logs: ${LOG_DIR}/"
