Building PolarSSL for android.

First, build static OpenSSL for PolarSSL/OpenSSL bridge
(the build-openssl-small script may be used).

Next build libminicrypto.a from libcrypto.a :

  $OVPN3_DIR/polarssl/build-mini-openssl ref

Finally, build PolarSSL:

  TARGET=android $OVPN3_DIR/polarssl/build-polarssl
