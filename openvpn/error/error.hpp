#ifndef OPENVPN_ERROR_ERROR_H
#define OPENVPN_ERROR_ERROR_H

namespace openvpn {
  namespace Error {

    enum Type {
      SUCCESS=0,           // no error
      NETWORK_ERROR,       // errors on network socket
      DECRYPT_ERROR,       // data channel encrypt/decrypt error
      HMAC_ERROR,          // HMAC verification failure
      REPLAY_ERROR,        // error from PacketIDReceive
      BUFFER_ERROR,        // exception thrown in Buffer methods
      CC_ERROR,            // general control channel errors
      BAD_SRC_ADDR,        // packet from unknown source address
      COMPRESS_ERROR,      // compress/decompress errors on data channel
      RESOLVE_ERROR,       // DNS resolution error
      SOCKET_PROTECT_ERROR, // Error calling protect() method on socket
      TUN_NET_ERROR,       // read/write errors on tun/tap interface
      TUN_SETUP_FAILED,    // error setting up tun/tap interface
      TCP_OVERFLOW,        // TCP output queue overflow
      TCP_SIZE_ERROR,      // bad embedded uint16_t TCP packet size
      TCP_CONNECT_ERROR,   // client error on TCP connect
      SSL_ERROR,           // errors resulting from read/write on SSL object
      ENCAPSULATION_ERROR, // exceptions thrown during packet encapsulation
      HANDSHAKE_TIMEOUT,   // handshake failed to complete within given time frame
      KEEPALIVE_TIMEOUT,   // lost contact with peer
      PRIMARY_EXPIRE,      // primary key context expired
      CERT_VERIFY_FAIL,    // peer certificate verification failure
      AUTH_FAILED,         // general authentication failure
      N_ERRORS,
    };

    inline const char *name(const size_t type)
    {
      static const char *names[] = {
	"SUCCESS",
	"NETWORK_ERROR",
	"DECRYPT_ERROR",
	"HMAC_ERROR",
	"REPLAY_ERROR",
	"BUFFER_ERROR",
	"CC_ERROR",
	"BAD_SRC_ADDR",
	"COMPRESS_ERROR",
	"RESOLVE_ERROR",
	"SOCKET_PROTECT_ERROR",
	"TUN_NET_ERROR",
	"TUN_SETUP_FAILED",
	"TCP_OVERFLOW",
	"TCP_SIZE_ERROR",
	"TCP_CONNECT_ERROR",
	"SSL_ERROR",
	"ENCAPSULATION_ERROR",
	"HANDSHAKE_TIMEOUT",
	"KEEPALIVE_TIMEOUT",
	"PRIMARY_EXPIRE",
	"CERT_VERIFY_FAIL",
	"AUTH_FAILED",
      };

      if (type < N_ERRORS)
	return names[type];
      else
	return "UNKNOWN_ERROR_TYPE";
    }
  }
} // namespace openvpn

#endif // OPENVPN_ERROR_ERROR_H
