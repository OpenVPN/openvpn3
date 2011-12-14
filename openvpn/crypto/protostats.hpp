#ifndef OPENVPN_CRYPTO_PROTOSTATS_H
#define OPENVPN_CRYPTO_PROTOSTATS_H

#include <cstring>

#include <openvpn/common/log.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class ProtoStats : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ProtoStats> Ptr;

    enum {
      // operating stats
      BYTES_IN = 0,
      BYTES_OUT,

      // error stats
      HMAC_ERRORS,        // HMAC verification failure (assumed to be first error by error() method below)
      REPLAY_ERRORS,      // error from PacketIDReceive
      CRYPTO_ERRORS,      // data channel encrypt/decrypt error
      COMPRESS_ERRORS,    // compress/decompress errors on data channel
      BUFFER_ERRORS,      // exception thrown in Buffer methods
      CC_ERRORS,          // general control channel errors
      SSL_ERRORS,         // errors resulting from read/write on SSL object
      HANDSHAKE_ERRORS,   // handshake failed to complete within given time frame
      DISCONNECTS,        // unintentional disconnects
      CERT_VERIFY_FAILS,  // peer certificate verification failure
      AUTH_FAILS,         // general authentication failure
      N_ITEMS,
    };

    ProtoStats()
    {
      std::memset(data, 0, sizeof(data));
    }

    void error(const size_t err_type)
    {
      //OPENVPN_LOG("*** ERROR " << err_type);
      if (err_type > HMAC_ERRORS && err_type < N_ITEMS)
	++data[err_type];
    }

  private:
    count_t data[N_ITEMS];
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_PROTOSTATS_H
