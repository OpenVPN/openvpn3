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
    friend class OpenVPNStaticKey;
    typedef BufferAllocatedType<unsigned char> key_t;

  public:
    StaticKey() {}
    StaticKey(const unsigned char *key_data, const size_t key_size)
      : key_data_(key_data, key_size, key_t::DESTRUCT_ZERO) {}

    size_t size() const { return key_data_.size(); }
    const unsigned char *data() const { return key_data_.c_data(); }
    void erase() { key_data_.clear(); }

    std::string render_hex() const { return openvpn::render_hex(key_data_); }

  private:
    key_t key_data_;
  };

  class OpenVPNStaticKey
  {
    typedef StaticKey::key_t key_t;

  public:
    enum {
      KEY_SIZE = 256 // bytes
    };

    // key specifier
    enum {
      // key for cipher and hmac
      CIPHER = 0,
      HMAC = (1<<0),

      // do we want to encrypt or decrypt with this key
      ENCRYPT = 0,
      DECRYPT = (1<<1),

      // key direction
      NORMAL = 0,
      INVERSE = (1<<2)
    };

    OPENVPN_SIMPLE_EXCEPTION(static_key_parse_error);
    OPENVPN_SIMPLE_EXCEPTION(static_key_bad_size);

    StaticKey slice(unsigned int key_specifier)
    {
      if (key_data_.size() != KEY_SIZE)
	throw static_key_bad_size();
      static const unsigned char key_table[] = { 0, 1, 2, 3, 2, 3, 0, 1 };
      const unsigned int idx = key_table[key_specifier & 7] * 64;
      return StaticKey(key_data_.c_data() + idx, KEY_SIZE / 4);
    }

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
      key_data_ = data;
    }

    std::string render() const
    {
      if (key_data_.size() != KEY_SIZE)
	throw static_key_bad_size();
      std::ostringstream out;
      out << static_key_head << "\n";
      for (size_t i = 0; i < KEY_SIZE; i += 16)
	out << render_hex(key_data_.c_data() + i, 16) << "\n";
      out << static_key_foot << "\n";
      return out.str();
    }

  private:
    static const char static_key_head[];
    static const char static_key_foot[];

    key_t key_data_;
  };

  const char OpenVPNStaticKey::static_key_head[] = "-----BEGIN OpenVPN Static key V1-----"; // CONST GLOBAL
  const char OpenVPNStaticKey::static_key_foot[] = "-----END OpenVPN Static key V1-----"; // CONST GLOBAL

} // namespace openvpn

#endif // OPENVPN_CRYPTO_STATIC_KEY_H
