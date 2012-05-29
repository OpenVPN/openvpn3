Building proto.cpp sample:

On Apple:

  Build with Apple SSL client and OpenSSL (osx default) server:

    OPENSSL_DIR="" SSL_BOTH=1 build proto

  Build with Apple SSL client and OpenSSL (custom build) server:

    SSL_BOTH=1 build proto

  Build with OpenSSL client and OpenSSL server (custom build):

    OSSL=1 build proto

  Build with PolarSSL client and OpenSSL server (custom build):

    PSSL=1 OSSL=1 build proto

On linux:

  Build with OpenSSL:

    build proto

  Build with PolarSSL:

    PSSL=1 build proto
