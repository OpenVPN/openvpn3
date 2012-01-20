Building proto.cpp sample:

On Apple:

  Build with Apple SSL client and OpenSSL server:

    SSL_BOTH=1 GCC_EXTRA="-DITER=10001 -DSITER=100 -DN_THREADS=4" build proto 2>&1 | g 'error:[^:]'

  Build with OpenSSL client and OpenSSL server:

    OSSL=1 GCC_EXTRA="-DITER=10001 -DSITER=100 -DN_THREADS=4" build proto 2>&1 | g 'error:[^:]'

On linux with AES NI:

  GCC_EXTRA="-DOPENSSL_AES_NI" build proto

On regular linux:

  build proto
