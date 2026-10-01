#!/bin/bash
#
# Regenerates the certificates used by the remote-cert-tls, remote-cert-ku and
# remote-cert-eku unit tests. Each is signed by ca.crt / ca.key and has the CA's
# validity period. Only the keys that a handshake test needs are kept. Needs
# OpenSSL 3.4 or later, for -not_before / -not_after.

set -euo pipefail
cd "$(dirname "$0")"

# notBefore=2024-10-21 14:56:07Z -> 20241021145607Z
ca_date()
{
    openssl x509 -in ca.crt -noout -dateopt iso_8601 "$1" | cut -d= -f2 | tr -d ' :-'
}
not_before=$(ca_date -startdate)
not_after=$(ca_date -enddate)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# gen NAME CN KEY_USAGE EXTENDED_KEY_USAGE KEEP_KEY
# An empty KEY_USAGE or EXTENDED_KEY_USAGE leaves that extension out.
gen()
{
    local name=$1 cn=$2 ku=$3 eku=$4 keep_key=$5
    local ext="$tmp/$name.ext"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/$name.key"

    printf 'basicConstraints = CA:FALSE\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n' >"$ext"
    if [ -n "$ku" ]; then
        echo "keyUsage = $ku" >>"$ext"
    fi
    if [ -n "$eku" ]; then
        echo "extendedKeyUsage = $eku" >>"$ext"
    fi

    openssl req -new -key "$tmp/$name.key" -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=$cn" -out "$tmp/$name.csr"
    openssl x509 -req -in "$tmp/$name.csr" -CA ca.crt -CAkey ca.key \
        -set_serial "0x$(openssl rand -hex 8)" -not_before "$not_before" -not_after "$not_after" \
        -sha256 -extfile "$ext" -out "$tmp/$name.crt"

    outputs+=("$name.crt")
    if [ "$keep_key" = 1 ]; then
        outputs+=("$name.key")
    fi
}

# nothing in this directory changes until every certificate is signed
outputs=()
gen server-noeku Test-Server-NoEKU "digitalSignature, keyEncipherment" "" 1
gen server-noku Test-Server-NoKU "" "serverAuth" 1
gen server-ds Test-Server-DS "digitalSignature" "serverAuth" 0
gen server-a8 Test-Server-A8 "digitalSignature, keyEncipherment, keyAgreement" "serverAuth" 0
gen server-anyeku Test-Server-AnyEKU "digitalSignature, keyEncipherment" "anyExtendedKeyUsage" 0
gen server-clienteku Test-Server-ClientEKU "digitalSignature, keyEncipherment" "clientAuth" 0
gen client-eku Test-Client-EKU "digitalSignature" "clientAuth" 1

for f in "${outputs[@]}"; do
    mv -f "$tmp/$f" "$f"
done
