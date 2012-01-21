#ifndef OPENVPN_TUN_CLIENT_TUNBASE_H
#define OPENVPN_TUN_CLIENT_TUNBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/transport/client/transbase.hpp>

namespace openvpn {

  struct TunClient : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClient> Ptr;

    virtual void client_start(const OptionList&, TransportClient&) = 0;
    virtual void stop() = 0;
    virtual bool tun_send(BufferAllocated& buf) = 0; // return true if send succeeded
    virtual std::string tun_name() const = 0;
  };

  struct TunClientParent
  {
    virtual void tun_recv(BufferAllocated& buf) = 0;
    virtual void tun_connected() {}
    virtual void tun_error(const std::exception&) {}
  };

  struct TunClientFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClientFactory> Ptr;

    virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					  TunClientParent& parent) = 0;
  };

} // namespace openvpn

#endif // OPENVPN_TUN_CLIENT_TUNBASE_H
