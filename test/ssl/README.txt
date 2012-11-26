Building proto.cpp sample:

On Apple:

  Build with PolarSSL client and server (no ASM crypto algs):

    GCC_EXTRA="-ferror-limit=4 -DUSE_POLARSSL_SERVER" PSSL=1 SNAP=1 OPENSSL_LINK=1 build proto

On linux:

  Build with OpenSSL:

    build proto

  Build with PolarSSL client:

    PSSL=1 build proto
