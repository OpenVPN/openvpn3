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

Typical output:

  $ time ./proto
  *** app bytes=73301015 net_bytes=146383320 data_bytes=36327640 prog=0000218807/0000218806 D=12600/600/12600/800 N=1982/1982 SH=17800/17800 HE=3/6
  real	0m11.003s
  user	0m10.981s
  sys	0m0.004s
