#!/bin/sh
set -eux

PREFIX="${PREFIX:-${HOME}/opt}"

if [ "${TRAVIS_OS_NAME}" = "linux" ]; then
    export LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH:-}"
fi

if [ "${TRAVIS_OS_NAME}" = "osx"   ]; then
    export DYLD_LIBRARY_PATH="${PREFIX}/lib:${DYLD_LIBRARY_PATH:-}"
fi


if [ "${SSLLIB}" = "openssl" ]; then
    SSL_LIBS="${OPENSSL_LIBS}"
    SSL_CFLAGS="-DUSE_OPENSSL"
elif [ "${SSLLIB}" = "mbedtls" ]; then
    SSL_LIBS="${MBEDTLS_LIBS}"
    SSL_CFLAGS="-DUSE_MBEDTLS"
else
    echo "Invalid crypto lib: ${SSLLIB}"
    exit 1
fi


CXXFLAGS="-O3 -std=c++14 -Wall -pthread \
          -DOPENVPN_SHOW_SESSION_TOKEN -DHAVE_LZ4 \
          -DUSE_ASIO -DASIO_STANDALONE -DASIO_NO_DEPRECATED ${SSL_CFLAGS}"

if [[ "${CC}" == "gcc"* ]]; then
    CXXFLAGS="${CXXFLAGS} -fwhole-program -flto=4"
fi

INCLUDEDIRS="-I../../asio/asio/include -I${PREFIX}/include -I../../"
LDFLAGS="-L${PREFIX}/lib"

if [ "${TRAVIS_OS_NAME}" = "linux" ]; then
    LDFLAGS="${LDFLAGS} -Wl,--no-as-needed"
fi

LIBS="${SSL_LIBS} -llz4"

(
    cd test/ovpncli
    ${CXX} ${CXXFLAGS} ${INCLUDEDIRS} ${LDFLAGS} cli.cpp -o cli ${LIBS}
)

(
    cd test/ssl
    ${CXX} ${CXXFLAGS} ${INCLUDEDIRS} ${LDFLAGS} proto.cpp -o proto ${LIBS}
    ./proto
)
