#ifndef OPENVPN_TUN_TUNPOSIX_H
#define OPENVPN_TUN_TUNPOSIX_H

#include <boost/noncopyable.hpp>
#include <boost/intrusive_ptr.hpp>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

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
