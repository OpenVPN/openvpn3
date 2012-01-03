#ifndef OPENVPN_TUN_TUNBASE_H
#define OPENVPN_TUN_TUNBASE_H

#include <string>

#include <openvpn/common/rc.hpp>

namespace openvpn {

  struct TunBase : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunBase> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool tun_send(BufferAllocated& buf) = 0;
  };

  struct TunParent
  {
    virtual void tun_recv(BufferAllocated& buf) = 0;
    virtual void tun_connected() {}
    virtual void tun_error(const std::string) {}
  };

  struct TunFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunFactory> Ptr;

    virtual TunBase::Ptr new_obj(boost::asio::io_service& io_service,
				 TunParent& parent) = 0;
  };

} // namespace openvpn

#endif // OPENVPN_TUN_TUNBASE_H
