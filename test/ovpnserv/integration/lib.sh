#!/bin/bash
# lib.sh — Shared helpers for O3 server integration tests.
#
# Sourced, not executed. test_server_classic.sh and test_server_dco.sh are
# structurally near-identical (netns/veth setup, handshake wait, ping through
# the tunnel, stop-and-verify-unreachable) with only the server invocation and
# the netdev-type assertion differing, so the shared shape lives here rather
# than being copied a second time. Every function takes the caller's
# namespace/veth/log names as arguments instead of assuming variable names, so
# callers keep their own naming.

# Scales a timeout by $TIMEOUT_SCALE (default 1), so a sanitizer build needs no
# edits to any script sourcing this file.
scaled() {
    echo $(($1 * "${TIMEOUT_SCALE:-1}"))
}

ns_exec() { ip netns exec "$1" "${@:2}"; }
ns_bg() { exec nsenter --net="/run/netns/$1" -- "${@:2}"; }

# Create a server/client namespace pair connected by a veth link. Deletes any
# stale leftovers under the same names first, matching what the caller's own
# cleanup trap does at exit.
# Usage: netns_setup NS_SERVER NS_CLIENT VETH_SERVER VETH_CLIENT SERVER_IP CLIENT_IP
netns_setup() {
    local ns_server="$1" ns_client="$2" veth_server="$3" veth_client="$4"
    local server_ip="$5" client_ip="$6"

    ip netns del "${ns_server}" 2>/dev/null || true
    ip netns del "${ns_client}" 2>/dev/null || true
    ip link del "${veth_server}" 2>/dev/null || true

    ip netns add "${ns_server}"
    ip netns add "${ns_client}"
    ip link add "${veth_server}" type veth peer name "${veth_client}"
    ip link set "${veth_server}" netns "${ns_server}"
    ip link set "${veth_client}" netns "${ns_client}"
    ns_exec "${ns_server}" ip addr add "${server_ip}/24" dev "${veth_server}"
    ns_exec "${ns_server}" ip link set "${veth_server}" up
    ns_exec "${ns_server}" ip link set lo up
    ns_exec "${ns_client}" ip addr add "${client_ip}/24" dev "${veth_client}"
    ns_exec "${ns_client}" ip link set "${veth_client}" up
    ns_exec "${ns_client}" ip link set lo up
}

# Usage: netns_teardown NS_SERVER NS_CLIENT VETH_SERVER
netns_teardown() {
    ip netns del "$1" 2>/dev/null || true
    ip netns del "$2" 2>/dev/null || true
    ip link del "$3" 2>/dev/null || true
}

# ── Multi-client topology ────────────────────────────────────────────
#
# A single veth pair cannot carry more than one client, so anything testing
# behaviour *between* clients (client-to-client policy, reverse-path filtering,
# concurrent sessions) needs a bridge with one namespace per client:
#
#   ns-<p>-br   [br0]  ──┬── v<p>s  ←→  ns-<p>-srv   <base>.1
#                        ├── v<p>c0 ←→  ns-<p>-c0    <base>.10
#                        └── v<p>c1 ←→  ns-<p>-c1    <base>.11
#
# Names derive from a caller-supplied prefix so two suites can run
# concurrently under ctest without colliding on namespace or link names.
# Namespaces can be named freely; link names cannot -- IFNAMSIZ caps them at
# 15 characters and the bridge side adds one more, so mc_link rejects an
# over-long prefix with a message instead of leaving `ip` to report
# "Attribute failed policy validation".

# Namespace name for the bridge / server / Nth client of a topology.
mc_ns_bridge() { echo "ns-$1-br"; }
mc_ns_server() { echo "ns-$1-srv"; }
mc_ns_client() { echo "ns-$1-c$2"; }

# Underlay address of the server / Nth client. $2 is the /24 base, e.g. 10.99.0
mc_server_ip() { echo "$2.1"; }
mc_client_ip() { echo "$2.$((10 + $3))"; }

# Link name for one end of a topology veth. Usage: mc_link PREFIX SUFFIX
mc_link() {
    local name="v$1$2"
    if ((${#name} > 14)); then
        echo "lib.sh: link name '${name}b' exceeds IFNAMSIZ; shorten the topology prefix '$1'" >&2
        return 1
    fi
    echo "${name}"
}

# Build a bridge + server + N client namespaces. Idempotent: tears down any
# stale topology under the same prefix first.
# Usage: mc_setup PREFIX SUBNET_BASE N_CLIENTS
mc_setup() {
    local p="$1" base="$2" n="$3" i

    mc_teardown "${p}" "${n}"

    ip netns add "$(mc_ns_bridge "${p}")"
    ns_exec "$(mc_ns_bridge "${p}")" ip link add br0 type bridge
    ns_exec "$(mc_ns_bridge "${p}")" ip link set br0 up
    ns_exec "$(mc_ns_bridge "${p}")" ip link set lo up

    mc_attach "${p}" "$(mc_ns_server "${p}")" "$(mc_link "${p}" s)" \
        "$(mc_server_ip "${p}" "${base}")"
    for ((i = 0; i < n; i++)); do
        mc_attach "${p}" "$(mc_ns_client "${p}" "${i}")" "$(mc_link "${p}" "c${i}")" \
            "$(mc_client_ip "${p}" "${base}" "${i}")"
    done
}

# Attach one namespace to the topology's bridge with a veth pair.
# Usage: mc_attach PREFIX NS LINK_BASENAME IP
mc_attach() {
    local p="$1" ns="$2" link="$3" ip_addr="$4"
    local br="$(mc_ns_bridge "${p}")"

    ip netns add "${ns}"
    ip link add "${link}b" type veth peer name "${link}"
    ip link set "${link}b" netns "${br}"
    ip link set "${link}" netns "${ns}"

    ns_exec "${br}" ip link set "${link}b" master br0
    ns_exec "${br}" ip link set "${link}b" up
    ns_exec "${ns}" ip addr add "${ip_addr}/24" dev "${link}"
    ns_exec "${ns}" ip link set "${link}" up
    ns_exec "${ns}" ip link set lo up
}

# Usage: mc_teardown PREFIX N_CLIENTS
mc_teardown() {
    local p="$1" n="$2" i
    ip netns del "$(mc_ns_server "${p}")" 2>/dev/null || true
    for ((i = 0; i < n; i++)); do
        ip netns del "$(mc_ns_client "${p}" "${i}")" 2>/dev/null || true
    done
    ip netns del "$(mc_ns_bridge "${p}")" 2>/dev/null || true
    ip link del "v${p}s" 2>/dev/null || true
    for ((i = 0; i < n; i++)); do
        ip link del "v${p}c${i}" 2>/dev/null || true
    done
}

# Write a client profile pointing at the given server endpoint.
# Usage: write_client_profile PATH SSL_DIR SERVER_IP PORT [EXTRA_LINES...]
write_client_profile() {
    local path="$1" ssl="$2" server_ip="$3" port="$4"
    shift 4
    cat >"${path}" <<EOF
client
dev tun
proto udp4
remote ${server_ip} ${port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 4
ca ${ssl}/ca.crt
cert ${ssl}/client.crt
key ${ssl}/client.key
EOF
    local line
    for line in "$@"; do
        echo "${line}" >>"${path}"
    done
}

# The tunnel address a connected client was assigned, or empty.
# Usage: client_tun_ip NS
client_tun_ip() {
    ns_exec "$1" ip -4 addr show dev tun 2>/dev/null | grep -oP 'inet \K[0-9.]+' || true
}

# Poll a client log for "EVENT: CONNECTED", failing early if either process
# has already died rather than waiting out the full timeout.
# Usage: wait_for_connected CLIENT_LOG TIMEOUT_SECONDS SERVER_PID CLIENT_PID
# Returns 0 once connected, 1 on timeout or a dead process.
wait_for_connected() {
    local client_log="$1" timeout="$2" server_pid="$3" client_pid="$4"
    local elapsed=0
    while ((elapsed < timeout)); do
        grep -qi "EVENT: CONNECTED" "${client_log}" 2>/dev/null && return 0
        kill -0 "${server_pid}" 2>/dev/null || return 1
        kill -0 "${client_pid}" 2>/dev/null || return 1
        sleep 1
        ((elapsed++)) || true
    done
    return 1
}

# Poll a namespace until an IPv4 address appears on any of its interfaces.
#
# A client logs that it has connected slightly before its ifconfig has actually
# landed, so checking once right after that log line is a race: it holds on an
# idle machine and fails under `ctest -j32`, with the diagnostic dump that
# follows the failure showing the address present.
#
# Usage: wait_for_addr NS ADDR TIMEOUT_SECONDS
wait_for_addr() {
    local ns="$1" addr="$2" timeout="$3"
    local elapsed=0
    while ((elapsed < timeout)); do
        ns_exec "${ns}" ip -4 addr show 2>/dev/null | grep -q "inet ${addr}[/ ]" && return 0
        sleep 1
        ((elapsed++)) || true
    done
    return 1
}

# Skip with 77 unless ping is present. The build images ship iproute2 but not
# iputils-ping, so every test that measures reachability has to check first.
# Usage: require_ping
require_ping() {
    if ! command -v ping >/dev/null 2>&1; then
        echo "SKIP: ping required to verify tunnel reachability"
        exit 77
    fi
}

# Usage: ping_through_tunnel NS_CLIENT TARGET_IP COUNT TIMEOUT LOG_FILE
ping_through_tunnel() {
    local ns_client="$1" target_ip="$2" count="$3" timeout="$4" log_file="$5"
    ns_exec "${ns_client}" ping -c "${count}" -W "${timeout}" "${target_ip}" >"${log_file}" 2>&1
}

# Usage: verify_unreachable NS_CLIENT TARGET_IP
verify_unreachable() {
    ! ns_exec "$1" ping -c 1 -W 2 "$2" &>/dev/null
}

# Print a failure message with both logs tailed, then exit 1.
# Usage: fail MESSAGE SERVER_LOG CLIENT_LOG
fail() {
    echo "FAIL: $1"
    echo ""
    echo "--- Server log ---"
    tail -60 "$2" 2>/dev/null || echo "(no log)"
    echo ""
    echo "--- Client log ---"
    tail -60 "$3" 2>/dev/null || echo "(no log)"
    exit 1
}
