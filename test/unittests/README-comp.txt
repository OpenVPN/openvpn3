Test LZO-Asym correctness and performance:

  GCC_EXTRA="-DTEST_LZO_ASYM -DN_EXPAND=1000" LZO=1 build test && time ./test

Compare above LZO-Asym decompression with real LZO compressor:

  GCC_EXTRA="-DTEST_LZO -DN_EXPAND=1000" LZO=1 build test && time ./test

Compare Snappy with LZO performance:

  ASIO=1 GCC_EXTRA="-DTEST_SNAPPY -DN_COMPRESS=1000" SNAP=1 build test && time ./test
  ASIO=1 GCC_EXTRA="-DTEST_LZO -DN_COMPRESS=1000" LZO=1 build test && time ./test
