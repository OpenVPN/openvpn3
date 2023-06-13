OpenVPN protocol unit tests
===========================

The :code:`protoUnitTest` utility can be tweaked with build time options changing
the behaviour.  These are set via CMake variables.

* :code:`TEST_PROTO_NTHREADS` - Running test threads (default :code:`1`)

  The number of test client/server pairs running in parallel.

  ::

      $ cd $O3/core/build && cmake -DTEST_PROTO_NTHREADS=4 ..
      $ cmake --build . -- test/unittests/protoUnitTests

* :code:`TEST_PROTO_RENEG` - Rengotiation (default :code:`900`)

  To simulate less data-channel activity and more SSL renegotiations

  ::

      $ cd $O3/core/build && cmake -DTEST_PROTO_RENEG=90 ..
      $ cmake --build . -- test/unittests/protoUnitTests

* :code:`TEST_PROTO_ITER` - Iterations (default :code:`1000000`)

  For verbose output, lower the number of xmit/recv iterations by defining
  :code:`TEST_PROTO_ITER` to be :code:`10000` or less, e.g.

  ::

      $ cd $O3/core/build && cmake -DTEST_PROTO_ITER=1000 ..
      $ cmake --build . -- test/unittests/protoUnitTests

* :code:`TEST_PROTO_SITER` - High-level Session Iterations (default :code:`1`)

  ::

      $ cd $O3/core/build && cmake -DTEST_PROTO_SITER=2 ..
      $ cmake --build . -- test/unittests/protoUnitTests

* :code:`TEST_PROTO_VERBOSE` - Verbose log output (:code:`OFF`)

  This will dump details of the protocol traffic as the test runs.  This
  is a boolean flag.

  ::

      $ cd $O3/core/build && cmake -DTEST_PROTO_VERBOSE=ON ..
      $ cmake --build . -- test/unittests/protoUnitTests


Mbed TLS specific
-----------------

Caveats
~~~~~~~

When using MbedTLS as both client and server, make sure to build
MbedTLS on Mac OS X with :code:`OSX_SERVER=1`.


Typical output
--------------

  ::

      $ cd $O3/core/build
      $ cmake ..
      $ cmake --build . -- test/unittests/protoUnitTests
      $ time ./test/unittests/protoUnitTests
      [==========] Running 1 test from 1 test suite.
      [----------] Global test environment set-up.
      [----------] 1 test from proto
      [ RUN      ] proto.base_1_thread
      *** app bytes=127454208 net_bytes=196770417 data_bytes=415976439 prog=0000379325/0000379326 D=14700/600/12600/700 N=110/110 SH=14900/17300 HE=1/0
      [       OK ] proto.base_1_thread (12775 ms)
      [----------] 1 test from proto (12775 ms total)

      [----------] Global test environment tear-down
      [==========] 1 test from 1 test suite ran. (12775 ms total)
      [  PASSED  ] 1 test.

      real	0m12,794s
      user	0m12,518s
      sys	0m0,250s
