//
//  tunbase.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Abstract base classes for client tun interface objects.

#ifndef OPENVPN_TUN_CLIENT_TUNBASE_H
#define OPENVPN_TUN_CLIENT_TUNBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/transport/client/transbase.hpp>

namespace openvpn {

  // Base class for objects that implement a client tun interface.
  struct TunClient : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClient> Ptr;

    virtual void client_start(const OptionList&, TransportClient&) = 0;
    virtual void stop() = 0;
    virtual bool tun_send(BufferAllocated& buf) = 0; // return true if send succeeded
    virtual std::string tun_name() const = 0;
    virtual std::string vpn_ip4() const = 0;
    virtual std::string vpn_ip6() const = 0;
  };

  // Base class for parent of tun interface object, used to
  // communicate received data packets, exceptions, and progress
  // notifications.
  struct TunClientParent
  {
    virtual void tun_recv(BufferAllocated& buf) = 0;
    virtual void tun_error(const Error::Type fatal_err, const std::string& err_text) = 0;

    // progress notifications
    virtual void tun_pre_tun_config() = 0;
    virtual void tun_pre_route_config() = 0;
    virtual void tun_connected() = 0;
  };

  // Factory for tun interface objects.
  struct TunClientFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClientFactory> Ptr;

    virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					  TunClientParent& parent) = 0;

    // return true if layer 2 tunnels are supported
    virtual bool layer_2_supported() const { return false; }

    // called just prior to emission of Disconnect event
    virtual void close_persistent() {}
  };

} // namespace openvpn

#endif // OPENVPN_TUN_CLIENT_TUNBASE_H
