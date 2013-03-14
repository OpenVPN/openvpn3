Build on Mac:

  With PolarSSL:
    GCC_EXTRA="-ferror-limit=4" STRIP=1 PSSL=1 SNAP=1 build cli

  With OpenSSL:
    GCC_EXTRA="-ferror-limit=4" STRIP=1 OSSL=1 SNAP=1 build cli

Build on Linux:

  With OpenSSL:
    STRIP=1 SNAP=1 build cli

  With PolarSSL:
    STRIP=1 SNAP=1 PSSL=1 OPENSSL_LINK=1 build cli
