#ifndef OPENVPN_SSL_PSID_H
#define OPENVPN_SSL_PSID_H

#include <string>
#include <cstring>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/random/prng.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/memcmp.hpp>

namespace openvpn {

  class ProtoSessionID
  {
  public:
    enum {
      SIZE=8
    };

    ProtoSessionID()
    {
      reset();
    }

    void reset()
    {
      defined_ = false;
      std::memset(id_, 0, SIZE);
    }

    explicit ProtoSessionID(Buffer& buf)
    {
      buf.read(id_, SIZE);
      defined_ = true;
    }

    void randomize(PRNG& prng)
    {
      prng.bytes(id_, SIZE);
      defined_ = true;
    }

    void read(Buffer& buf)
    {
      buf.read(id_, SIZE);
      defined_ = true;
    }

    void write(Buffer& buf) const
    {
      buf.write(id_, SIZE);
    }

    void prepend(Buffer& buf) const
    {
      buf.prepend(id_, SIZE);
    }

    bool defined() const { return defined_; }

    bool match(const ProtoSessionID& other) const
    {
      return defined_ && other.defined_ && !memcmp_secure(id_, other.id_, SIZE);
    }

    std::string str() const
    {
      return render_hex(id_, SIZE);
    }

  protected:
    ProtoSessionID(const unsigned char *data)
    {
      std::memcpy(id_, data, SIZE);
    }

  private:
    bool defined_;
    unsigned char id_[SIZE];
  };
} // namespace openvpn

#endif // OPENVPN_SSL_PSID_H
