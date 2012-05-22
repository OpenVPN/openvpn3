Building proto.cpp sample:

On Apple:

  Build with Apple SSL client and OpenSSL server:

    clang: CLANG=1 LTO=1 SSL_BOTH=1 GCC_EXTRA="-DN_THREADS=4 -DITER=10001 -DSITER=100" build proto
    gcc:   SSL_BOTH=1 GCC_EXTRA="-DITER=10001 -DSITER=100 -DN_THREADS=4" build proto 2>&1 | g 'error:[^:]'

  Build with OpenSSL client and OpenSSL server:

    gcc: OSSL=1 GCC_EXTRA="-DITER=10001 -DSITER=100 -DN_THREADS=4" build proto 2>&1 | g 'error:[^:]'

On linux:

  build proto
