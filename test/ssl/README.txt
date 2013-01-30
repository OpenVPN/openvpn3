Building proto.cpp sample:

On Mac:

  Build with PolarSSL client and server (no ASM crypto algs):

    GCC_EXTRA="-ferror-limit=4 -DUSE_POLARSSL_SERVER" PSSL=1 SNAP=1 OSSL=1 build proto

  Build with PolarSSL client and OpenSSL server:

    GCC_EXTRA="-ferror-limit=4" PSSL=1 SNAP=1 OSSL=1 build proto

On Linux:

  Build with OpenSSL client and server:

    build proto

  Build with PolarSSL client and OpenSSL server:

    PSSL=1 build proto

Variations:

  For verbose output, lower the number of xmit/recv iterations by defining
  ITER to be 10000 or less, e.g.

    GCC_EXTRA="-DITER=1000" build proto
