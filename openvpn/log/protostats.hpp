#ifndef OPENVPN_LOG_PROTOSTATS_H
#define OPENVPN_LOG_PROTOSTATS_H

#include <cstring>

#include <openvpn/log/log.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class ProtoStats : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ProtoStats> Ptr;
    typedef size_t type_t;

    enum {
      // operating stats
      BYTES_IN = 0,
      BYTES_OUT,
      TUN_BYTES_IN,
      TUN_BYTES_OUT,

      // error stats
      NETWORK_ERROR,       // errors on network socket
      RESOLVE_ERROR,       // DNS resolution error
      TUN_ERROR,           // errors on tun/tap interface
      HMAC_ERROR,          // HMAC verification failure
      REPLAY_ERROR,        // error from PacketIDReceive
      CRYPTO_ERROR,        // data channel encrypt/decrypt error
      COMPRESS_ERROR,      // compress/decompress errors on data channel
      BUFFER_ERROR,        // exception thrown in Buffer methods
      CC_ERROR,            // general control channel errors
      SSL_ERROR,           // errors resulting from read/write on SSL object
      ENCAPSULATION_ERROR, // exceptions thrown during packet encapsulation
      HANDSHAKE_TIMEOUT,   // handshake failed to complete within given time frame
      KEEPALIVE_TIMEOUT,   // lost contact with peer
      PRIMARY_EXPIRE,      // primary key context expired
      CERT_VERIFY_FAIL,    // peer certificate verification failure
      AUTH_FAIL,           // general authentication failure
      N_ITEMS,
    };

    enum {
      ERROR_START = NETWORK_ERROR,
    };

    ProtoStats()
    {
      std::memset(data, 0, sizeof(data));
    }

    void error(const type_t err_type)
    {
#ifdef OPENVPN_DEBUG_PROTOSTATS
      OPENVPN_LOG("*** ERROR " << type_name(err_type));
#endif
      if (err_type >= ERROR_START && err_type < N_ITEMS)
	++data[err_type];
    }

    void inc_stat(const type_t type, const count_t value)
    {
      if (type < ERROR_START)
	data[type] += value;
    }

    count_t get(const type_t type) const
    {
      if (type < N_ITEMS)
	return data[type];
      else
	return 0;
    }

    const char *type_name(const type_t type)
    {
      static const char *names[] = {
      "BYTES_IN",
      "BYTES_OUT",
      "TUN_BYTES_IN",
      "TUN_BYTES_OUT",
      "NETWORK_ERROR",
      "RESOLVE_ERROR",
      "TUN_ERROR",
      "HMAC_ERROR",
      "REPLAY_ERROR",
      "CRYPTO_ERROR",
      "COMPRESS_ERROR",
      "BUFFER_ERROR",
      "CC_ERROR",
      "SSL_ERROR",
      "ENCAPSULATION_ERROR",
      "HANDSHAKE_TIMEOUT",
      "KEEPALIVE_TIMEOUT",
      "PRIMARY_EXPIRE",
      "CERT_VERIFY_FAIL",
      "AUTH_FAIL",
      };

      if (type < N_ITEMS)
	return names[type];
      else
	return "UNKNOWN_STAT_TYPE";
    }

  private:
    count_t data[N_ITEMS];
  };

} // namespace openvpn

#endif // OPENVPN_LOG_PROTOSTATS_H
