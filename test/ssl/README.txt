Building proto.cpp sample:

On Apple:

  Build with PolarSSL client and server (no ASM crypto algs):

    PSSL=1 NOSSL=1 GCC_EXTRA="-DUSE_POLARSSL_SERVER" build proto

On linux:

  Build with OpenSSL:

    build proto

  Build with PolarSSL client:

    PSSL=1 build proto
