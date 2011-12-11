Building proto.cpp sample:

On Apple:

  Build with Apple SSL client and OpenSSL server:

    SSL_BOTH=1 build proto 2>&1 | g 'error:[^:]'

  Build with OpenSSL client and OpenSSL server:

    OSSL=1 build proto 2>&1 | g 'error:[^:]'

On other unix:

  LTO=1 build proto
