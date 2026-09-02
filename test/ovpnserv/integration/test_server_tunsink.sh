#!/bin/bash
# test_server_nulltun.sh — Control-plane-only server integration test.
#
# Starts ovpnserv in --null-tun mode (no kernel netdev, no /dev/net/tun, no
# privilege of any kind -- see openvpn/server/tunsink.hpp) directly on
# loopback, no network namespaces needed. A CLI_NULLTUN-built ovpnclinull
# connects, reconnects, and disconnects repeatedly against the same
# long-running server.
#
# Runs the whole sequence once per control-channel mode, because the modes
# take materially different paths into the server:
#   none          PsidCookie::intercept() declines; validate_initial_packet()
#                 is the only pre-TLS filter.
#   tls-auth      the psid cookie gate runs, HMAC-only.
#   tls-crypt-v2  the cookie gate runs and additionally unwraps the client's
#                 WKc (psid_cookie_impl.hpp's init_tls_crypt_v2()).
# The last of those had no end-to-end coverage at all, which is how a stale
# "crashes on the first client packet" note survived in three places long
# after the underlying psid_cookie_impl.hpp bug was fixed upstream: the unit
# tests were green throughout because nobody assembled the real binary with
# the real flag.
#
# Validates, per mode:
#   - the client completes a real TLS handshake and receives EVENT: CONNECTED
#   - the server survives every connection (the tls-crypt-v2 crash guard)
#   - each dropped client is noticed by the server and reported to the
#     embedder's handler with reason=Timeout -- keepalive is turned right
#     down so the timeout path runs in seconds instead of the default minute
#   - it can do this repeatedly against one server process without the pool
#     running out -- the regression guard for the PeerRoutes address-pool
#     leak. --pool-size is deliberately set well below the reconnect count,
#     so an assign() whose release() never runs exhausts the pool and fails
#     the run rather than passing unnoticed inside a 252-address default.
#     This is why the run waits for each disconnect before reconnecting: a
#     session still holding its address is not a leak, and the wait is what
#     separates the two.
#   - stopping the server with a client still connected actually reaches that
#     client, which is checked by the client logging CLIENT_RESTART rather
#     than by the server logging that it tried (udptransserv.hpp sends the
#     RESTART before halt_ and link_->stop(), both of which make send_to()
#     refuse every datagram), and fires the embedder's disconnect callback
#     with reason=ServerShutdown (handler_man.hpp).
#
# This is deliberately not a data-plane test: --null-tun discards every
# packet, so there is nothing to ping. Tiers with a real tun device
# (test_server_classic.sh, test_server_dco.sh) cover that.
#
# Prerequisites:
#   - ovpnserv built; ovpncli built with -DCLI_NULLTUN=ON (produces
#     ovpnclinull)
#   - No privilege of any kind
#
# Usage: ./test_server_nulltun.sh [BUILD_DIR]
#   BUILD_DIR defaults to out/build/linux-x64-release under the repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORE_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${1:-${CORE_ROOT}/out/build/linux-x64-release}"

# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

SERV_BIN="${BUILD_DIR}/test/ovpnserv/ovpnserv"
CLI_BIN="${BUILD_DIR}/test/ovpncli/ovpnclinull"
SSL_DIR="${CORE_ROOT}/test/ssl"

SERVER_ADDR="127.0.0.1"
BASE_PORT=11494
RECONNECT_COUNT=6

# Smaller than RECONNECT_COUNT on purpose: see the pool note in the header.
POOL_SIZE=2
POOL_START="10.8.0.2"

# A dropped client is only noticed when keepalive gives up on it. The default
# 10/60 would make each iteration a minute long; 1/4 keeps the same code path
# and makes the run tractable.
KEEPALIVE_PING=1
KEEPALIVE_TIMEOUT=4
REAP_INTERVAL=1

# Run every mode by default; ctest passes one per test so the three run in
# parallel. Serially this is ~34s per mode, and three modes in one ctest entry
# exceeded its TIMEOUT on every build, ASAN or not -- the runtime is dominated
# by KEEPALIVE_TIMEOUT waits, so it does not shrink on faster hardware.
ALL_MODES=(none tls-auth tls-crypt-v2)
if [[ -n "${2:-}" ]]; then
    MODES=("$2")
else
    MODES=("${ALL_MODES[@]}")
fi

# Derived from the mode so parallel invocations never share a port or a log
# directory.
mode_index() {
    case "$1" in
    none) echo 1 ;;
    tls-auth) echo 2 ;;
    tls-crypt-v2) echo 3 ;;
    *)
        echo "unknown mode: $1" >&2
        exit 2
        ;;
    esac
}

HANDSHAKE_TIMEOUT="$(scaled 10)"
STOP_GRACE=2

LOG_DIR="/tmp/vpn-server-tunsink-it${2:+-$2}"

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
}
trap cleanup EXIT

# Extra ovpnserv arguments for a control-channel mode.
# Usage: server_args MODE
server_args() {
    case "$1" in
    none) ;;
    tls-auth) echo "--tls-auth ${SSL_DIR}/tls-auth.key --key-direction 0" ;;
    tls-crypt-v2) echo "--tls-crypt-v2 ${SSL_DIR}/tls-crypt-v2-server.key" ;;
    *)
        echo "unknown mode $1" >&2
        exit 1
        ;;
    esac
}

# The matching client directive for a control-channel mode.
# Usage: client_directive MODE
client_directive() {
    case "$1" in
    none) ;;
    tls-auth) echo "tls-auth ${SSL_DIR}/tls-auth.key 1" ;;
    tls-crypt-v2) echo "tls-crypt-v2 ${SSL_DIR}/tls-crypt-v2-client.key" ;;
    esac
}

# Usage: write_client_cfg MODE PORT PATH
write_client_cfg() {
    local mode="$1" port="$2" path="$3"
    cat >"${path}" <<EOF
client
dev tun
proto udp4
remote ${SERVER_ADDR} ${port}
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
$(client_directive "${mode}")
EOF
}

# Poll a log until PATTERN appears at least COUNT times.
# Usage: wait_for_count LOG PATTERN COUNT TIMEOUT_SECONDS
# Returns 0 once satisfied, 1 on timeout.
wait_for_count() {
    local log="$1" pattern="$2" want="$3" timeout="$4"
    local elapsed=0 have
    while ((elapsed < timeout)); do
        have=$(grep -c "${pattern}" "${log}" 2>/dev/null || true)
        ((have >= want)) && return 0
        sleep 1
        ((elapsed++)) || true
    done
    return 1
}

# Connect once, wait for CONNECTED, then stop the client.
# Usage: connect_once CLIENT_CFG CLIENT_LOG LABEL SERVER_LOG
connect_once() {
    local cfg="$1" log="$2" label="$3" server_log="$4"

    "${CLI_BIN}" "${cfg}" >"${log}" 2>&1 &
    CLIENT_PID=$!

    if ! wait_for_connected "${log}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
        fail "${label} did not reach CONNECTED within ${HANDSHAKE_TIMEOUT}s" "${server_log}" "${log}"
    fi

    kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    for _ in $(seq 1 "${STOP_GRACE}"); do
        kill -0 "${CLIENT_PID}" 2>/dev/null || break
        sleep 1
    done
    kill -9 "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
    CLIENT_PID=""
}

# ── Preconditions ────────────────────────────────────────────────────

echo "=== Server tun-sink (control-plane) integration test${2:+ -- mode $2} ==="

for bin in "${SERV_BIN}" "${CLI_BIN}"; do
    if [[ ! -x "${bin}" ]]; then
        echo "SKIP: binary not found at ${bin}"
        echo "      Build ovpnserv and ovpncli with -DCLI_NULLTUN=ON first."
        exit 77
    fi
done

mkdir -p "${LOG_DIR}"
rm -f "${LOG_DIR}"/*.log "${LOG_DIR}"/*.ovpn

# ── One full sequence per control-channel mode ───────────────────────

for mode in "${MODES[@]}"; do
    port=$((BASE_PORT + $(mode_index "${mode}")))
    server_log="${LOG_DIR}/server-${mode}.log"
    client_cfg="${LOG_DIR}/client-${mode}.ovpn"

    echo ""
    echo "--- Mode: ${mode} (port ${port}) ---"

    echo "[1/4] Starting null-tun ovpnserv..."
    # shellcheck disable=SC2046 # deliberate word splitting of server_args
    "${SERV_BIN}" \
        --ca "${SSL_DIR}/ca.crt" --cert "${SSL_DIR}/server.crt" --key "${SSL_DIR}/server.key" \
        --dh "${SSL_DIR}/dh.pem" --bind "${SERVER_ADDR}" --port "${port}" --null-tun \
        --pool-start "${POOL_START}" --pool-size "${POOL_SIZE}" \
        --keepalive "${KEEPALIVE_PING}" "${KEEPALIVE_TIMEOUT}" \
        --reap-interval "${REAP_INTERVAL}" \
        $(server_args "${mode}") \
        >"${server_log}" 2>&1 &
    SERVER_PID=$!
    sleep 2

    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        fail "Server exited immediately in mode ${mode}" "${server_log}" /dev/null
    fi
    echo "      Server PID: ${SERVER_PID}"

    write_client_cfg "${mode}" "${port}" "${client_cfg}"

    echo "[2/4] Connecting ${RECONNECT_COUNT}x against a ${POOL_SIZE}-address pool..."
    for ((i = 1; i <= RECONNECT_COUNT; i++)); do
        client_log="${LOG_DIR}/client-${mode}-${i}.log"
        connect_once "${client_cfg}" "${client_log}" "Connection ${i}/${RECONNECT_COUNT} (${mode})" "${server_log}"

        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            fail "Server died after connection ${i}/${RECONNECT_COUNT} in mode ${mode}" \
                "${server_log}" "${client_log}"
        fi

        # The address is only back in the pool once the session ends, which
        # is what makes the next iteration's assign() meaningful.
        if ! wait_for_count "${server_log}" "client disconnected:" "${i}" "$(scaled 20)"; then
            fail "Mode ${mode}: server never noticed client ${i} had gone" \
                "${server_log}" "${client_log}"
        fi
        echo "      [${i}/${RECONNECT_COUNT}] connected, then reported gone"
    done

    timeouts=$(grep -c "client disconnected: .*reason=Timeout" "${server_log}" || true)
    if [[ "${timeouts}" -ne "${RECONNECT_COUNT}" ]]; then
        fail "Mode ${mode}: ${timeouts} keepalive-timeout disconnects, expected ${RECONNECT_COUNT}" \
            "${server_log}" /dev/null
    fi

    if grep -q "address pool exhausted" "${server_log}"; then
        fail "Pool exhausted in mode ${mode}: an assigned address was never released" \
            "${server_log}" /dev/null
    fi

    connected=$(grep -c "client connected:" "${server_log}" || true)
    if [[ "${connected}" -ne "${RECONNECT_COUNT}" ]]; then
        fail "Mode ${mode}: server logged ${connected} connections, expected ${RECONNECT_COUNT}" \
            "${server_log}" /dev/null
    fi

    # ── Shutdown notification, with a client still attached ──────────
    echo "[3/4] Stopping the server with a client still connected..."
    client_log="${LOG_DIR}/client-${mode}-final.log"
    "${CLI_BIN}" "${client_cfg}" >"${client_log}" 2>&1 &
    CLIENT_PID=$!
    if ! wait_for_connected "${client_log}" "${HANDSHAKE_TIMEOUT}" "${SERVER_PID}" "${CLIENT_PID}"; then
        fail "Final connection (${mode}) did not reach CONNECTED" "${server_log}" "${client_log}"
    fi

    kill -TERM "${SERVER_PID}" 2>/dev/null || true
    for _ in $(seq 1 "$(scaled 5)"); do
        kill -0 "${SERVER_PID}" 2>/dev/null || break
        sleep 1
    done
    kill -9 "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
    SERVER_PID=""

    echo "[4/4] Checking the shutdown reached the client and the handler..."
    # Asserted on the client log, not the server's. The server logs
    # "Disconnect: RESTART" from push_halt_restart_msg() itself, whether or
    # not the datagram ever left -- so it stays green even when halt_ is set
    # first and send_to() refuses every one. Only the client having acted on
    # it proves the notification reached the wire.
    if ! wait_for_count "${client_log}" "CLIENT_RESTART" 1 "$(scaled 10)"; then
        fail "Mode ${mode}: client never saw the shutdown RESTART -- send_to() refused it" \
            "${server_log}" "${client_log}"
    fi

    kill -TERM "${CLIENT_PID}" 2>/dev/null || true
    kill -9 "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
    CLIENT_PID=""
    if ! grep -q "client disconnected: .*reason=ServerShutdown" "${server_log}"; then
        fail "Mode ${mode}: on_client_disconnected never fired with reason=ServerShutdown" \
            "${server_log}" "${client_log}"
    fi
    echo "      client saw CLIENT_RESTART; disconnect callback fired"
done

echo ""
echo "=== PASSED ==="
echo "    Modes: ${MODES[*]}"
echo "    ${RECONNECT_COUNT} reconnects each against a ${POOL_SIZE}-address pool"
echo "    every dropped client reported with reason=Timeout"
echo "    Shutdown reached the connected client in every mode"
echo "    Logs: ${LOG_DIR}/"
