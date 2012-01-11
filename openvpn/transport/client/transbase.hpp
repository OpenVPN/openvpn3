#ifndef OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
#define OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {

  struct TransportClient : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClient> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool transport_send_const(const Buffer& buf) = 0;
    virtual bool transport_send(BufferAllocated& buf) = 0;
    virtual std::string server_endpoint_render() const = 0;
    virtual IP::Addr server_endpoint_addr() const = 0;
  };

  struct TransportClientParent
  {
    virtual void transport_recv(BufferAllocated& buf) = 0;
    virtual void transport_connected() {}
    virtual void transport_error(const std::exception&) {}
  };

  struct TransportClientFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClientFactory> Ptr;

    virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						TransportClientParent& parent) = 0;
  };

} // namespace openvpn

#endif // OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
