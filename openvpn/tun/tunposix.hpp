#ifndef OPENVPN_TUN_TUNPOSIX_H
#define OPENVPN_TUN_TUNPOSIX_H

#include <boost/noncopyable.hpp>
#include <boost/exception/all.hpp>
#include <boost/intrusive_ptr.hpp>

#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

class TunPosix : boost::noncopyable {
public:
  // exceptions
  struct error : virtual std::exception, virtual boost::exception { };
  struct tun_open_error : virtual error { };
  struct tun_ioctl_error : virtual error { };
  struct tun_fcntl_error : virtual error { };
  struct tun_name_error : virtual error { };

  // typedefs
  typedef openvpn::BufferRC buffer;
  typedef boost::intrusive_ptr<buffer> buffer_ptr;

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
