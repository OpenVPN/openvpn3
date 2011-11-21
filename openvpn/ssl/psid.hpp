#ifndef OPENVPN_SSL_PSID_H
#define OPENVPN_SSL_PSID_H

#include <cstring>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/random/prng.hpp>

namespace openvpn {

  class ProtoSessionID
  {
  public:
    enum {
      SIZE=8
    };

    ProtoSessionID()
    {
      std::memset(id_, 0, SIZE);
    }

    void init(PRNG& prng)
    {
      prng.bytes(id_, SIZE);
    }

    void write(Buffer& buf) const
    {
      buf.write(id_, SIZE);
    }

  protected:
    ProtoSessionID(const unsigned char *data)
    {
      std::memcpy(id_, data, SIZE);
    }

  private:
    unsigned char id_[SIZE];
  };
} // namespace openvpn

#endif // OPENVPN_SSL_PSID_H
