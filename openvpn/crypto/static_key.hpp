#ifndef OPENVPN_CRYPTO_STATIC_KEY_H
#define OPENVPN_CRYPTO_STATIC_KEY_H

#include <string>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {
  class StaticKey
  {
  protected:
    typedef BufferAllocatedType<unsigned char> key_t;
  public:

  protected:
    key_t key_data;
  };

  class OpenVPNStaticKey : public StaticKey
  {
  public:
    enum {
      KEY_SIZE = 256 // bytes
    };

    OPENVPN_SIMPLE_EXCEPTION(static_key_parse_error);
    OPENVPN_SIMPLE_EXCEPTION(static_key_bad_render_size);

    void parse(const std::string& key_text)
    {
      std::stringstream in(key_text);
      key_t data(KEY_SIZE, key_t::DESTRUCT_ZERO);
      std::string line;
      bool in_body = false;
      while (std::getline(in, line))
	{
	  boost::trim(line);
	  if (line == static_key_head)
	    in_body = true;
	  else if (line == static_key_foot)
	    in_body = false;
	  else if (in_body)
	    parse_hex(data, line);
	}
      if (in_body || data.size() != KEY_SIZE)
	throw static_key_parse_error();
      key_data = data;
    }

    std::string render() const
    {
      if (key_data.size() != KEY_SIZE)
	throw static_key_bad_render_size();
      std::ostringstream out;
      out << static_key_head << "\n";
      for (size_t i = 0; i < KEY_SIZE; i += 16)
	out << render_hex(key_data.c_data() + i, 16) << "\n";
      out << static_key_foot << "\n";
      return out.str();
    }

  private:
    static const char static_key_head[];
    static const char static_key_foot[];
  };

  const char OpenVPNStaticKey::static_key_head[] = "-----BEGIN OpenVPN Static key V1-----"; // CONST GLOBAL
  const char OpenVPNStaticKey::static_key_foot[] = "-----END OpenVPN Static key V1-----"; // CONST GLOBAL

} // namespace openvpn

#endif // OPENVPN_CRYPTO_STATIC_KEY_H
