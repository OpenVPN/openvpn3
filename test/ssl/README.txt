Building proto.cpp sample:

On Apple:

  Build with PolarSSL client and server (no ASM crypto algs):

    GCC_EXTRA="-ferror-limit=4 -DUSE_POLARSSL_SERVER" PSSL=1 SNAP=1 OSSL=1 build proto

  Build with PolarSSL client and OpenSSL server:

    GCC_EXTRA="-ferror-limit=4" PSSL=1 SNAP=1 OSSL=1 build proto

On linux:

  Build with OpenSSL client and server:

    build proto

  Build with PolarSSL client and OpenSSL server:

    PSSL=1 build proto
