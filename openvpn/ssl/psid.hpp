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

    void randomize(PRNG& prng)
    {
      prng.bytes(id_, SIZE);
    }

    void read(Buffer& buf)
    {
      buf.read(id_, SIZE);
    }

    void write(Buffer& buf) const
    {
      buf.write(id_, SIZE);
    }

    void prepend(Buffer& buf) const
    {
      buf.prepend(id_, SIZE);
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
