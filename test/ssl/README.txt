Building proto.cpp sample:

On Apple:

  Build with Apple SSL client and OpenSSL server:

    SSL_BOTH=1 GCC_EXTRA="-DN_THREADS=4 -DITER=10001 -DSITER=100" build proto

  Build with OpenSSL client and OpenSSL server:

    OSSL=1 GCC_EXTRA="-DITER=10001 -DSITER=100 -DN_THREADS=4" build proto

On linux:

  Build with OpenSSL:

    build proto

  Build with PolarSSL:

    PSSL=1 build proto
