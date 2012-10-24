//
//  transbase.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
#define OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {

  struct TransportClient : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClient> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool transport_send_const(const Buffer& buf) = 0;
    virtual bool transport_send(BufferAllocated& buf) = 0;
    virtual IP::Addr server_endpoint_addr() const = 0;
    virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const = 0;
  };

  struct TransportClientParent
  {
    virtual void transport_recv(BufferAllocated& buf) = 0;
    virtual void transport_error(const Error::Type fatal_err, const std::string& err_text) = 0;
    virtual void proxy_error(const Error::Type fatal_err, const std::string& err_text) = 0;

    // progress notifications
    virtual void transport_pre_resolve() = 0;
    virtual void transport_connecting() = 0;
  };

  struct TransportClientFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClientFactory> Ptr;

    virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						TransportClientParent& parent) = 0;
  };

} // namespace openvpn

#endif // OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
