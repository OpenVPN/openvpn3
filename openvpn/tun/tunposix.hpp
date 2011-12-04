#ifndef OPENVPN_TUN_TUNPOSIX_H
#define OPENVPN_TUN_TUNPOSIX_H

#include <boost/noncopyable.hpp>
#include <boost/algorithm/string.hpp>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  struct ParseTunSpec
  {
    OPENVPN_EXCEPTION(bad_tun_spec);

    ParseTunSpec(const std::string& tun_spec)
      : ipv6(false)
    {
      std::vector<std::string> s;
      boost::split(s, tun_spec, boost::is_any_of("/"));
      if (s.size() == 1)
	{
	  tun_name = s[0];
	}
      else if (s.size() == 2)
	{
	  tun_name = s[0];
	  if (s[1] == "v4")
	    ipv6 = false;
	  else if (s[1] == "v6")
	    ipv6 = true;
	  else
	    throw bad_tun_spec();
	}
      else
	throw bad_tun_spec();
    }
    bool ipv6;
    std::string tun_name;
  };

class TunPosix : boost::noncopyable {
public:
  // exceptions
  OPENVPN_EXCEPTION(tun_open_error);
  OPENVPN_EXCEPTION(tun_ioctl_error);
  OPENVPN_EXCEPTION(tun_fcntl_error);
  OPENVPN_EXCEPTION(tun_name_error);
  OPENVPN_EXCEPTION(tun_partial_write);

  const char *name(void) const {
    return name_.c_str();
  }

  virtual ~TunPosix() {
  }

protected:
  std::string name_;
};

} // namespace openvpn

#endif // OPENVPN_TUN_TUNPOSIX_H
