//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Client tun interface for Mac OS X

#ifndef OPENVPN_TUN_MAC_CLIENT_TUNCLI_H
#define OPENVPN_TUN_MAC_CLIENT_TUNCLI_H

#include <string>
#include <sstream>
#include <memory>

#include <openvpn/common/format.hpp>
#include <openvpn/common/scoped_asio_stream.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunwrap.hpp>
#include <openvpn/tun/persist/tunwrapasio.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/mac/client/tunsetup.hpp>

#ifdef TEST_EER // test emulated exclude routes
#include <openvpn/client/cliemuexr.hpp>
#endif

namespace openvpn {
  namespace TunMac {

    OPENVPN_EXCEPTION(tun_mac_error);

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // tun interface wrapper for Mac OS X
    template <typename ReadHandler, typename TunWrap>
    class Tun : public TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunWrap> >
    {
      typedef TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunWrap>  > Base;

    public:
      typedef RCPtr<Tun> Ptr;

      Tun(const typename TunWrap::Ptr& tun_wrap,
	  const std::string& name,
	  const bool retain_stream,
	  const bool tun_prefix,
	  ReadHandler read_handler,
	  const Frame::Ptr& frame,
	  const SessionStats::Ptr& stats)
	: Base(read_handler, frame, stats)
      {
	Base::name_ = name;
	Base::retain_stream = retain_stream;
	Base::tun_prefix = tun_prefix;
	Base::stream = new TunWrapAsioStream<TunWrap>(tun_wrap);
      }
    };

    // These types manage the underlying tun driver fd
    typedef asio::posix::stream_descriptor TUNStream;
    typedef ScopedAsioStream<TUNStream> ScopedTUNStream;
    typedef TunWrapTemplate<ScopedTUNStream> TunWrap;

    class Client;

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef RCPtr<ClientConfig> Ptr;

      Layer layer;               // OSI layer

      TunProp::Config tun_prop;
      int n_parallel = 8;        // number of parallel async reads on tun socket

      bool enable_failsafe_block = false;

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      Stop* stop = nullptr;

      TunBuilderSetup::Factory::Ptr tun_setup_factory;

      TunBuilderSetup::Base::Ptr new_setup_obj()
      {
	if (tun_setup_factory)
	  return tun_setup_factory->new_setup_obj();
	else
	  return new TunMac::Setup();
      }

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_tun_client_obj(asio::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);

      // return true if layer 2 tunnels are supported
      virtual bool layer_2_supported() const
      {
#       if defined(MAC_TUNTAP_FALLBACK)
	  return false; // change to true after TAP support is added
#       else
	  return false; // utun device doesn't support TAP
#       endif
      }

      // called just prior to transmission of Disconnect event
      virtual void finalize(const bool disconnected)
      {
      }
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, TunWrapAsioStream<TunWrap> >;  // calls tun_read_handler

      typedef Tun<Client*, TunWrap> TunImpl;

    public:
      virtual void tun_start(const OptionList& opt, TransportClient& transcli, CryptoDCSettings&)
      {
	if (!impl)
	  {
	    halt = false;
	    tun_wrap.reset(new TunWrap(false));

	    try {
	      const IP::Addr server_addr = transcli.server_endpoint_addr();

	      // notify parent
	      parent.tun_pre_tun_config();

	      // emulated exclude routes
	      EmulateExcludeRouteFactory::Ptr eer_factory;
#ifdef TEST_EER
	      eer_factory.reset(new EmulateExcludeRouteFactoryImpl(true));
#endif
	      // parse pushed options
	      TunBuilderCapture::Ptr po(new TunBuilderCapture());
	      TunProp::configure_builder(po.get(),
					 state.get(),
					 config->stats.get(),
					 server_addr,
					 config->tun_prop,
					 opt,
					 eer_factory.get(),
					 false);

	      // handle MTU default
	      if (!po->mtu)
		po->mtu = 1500;

	      OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string());

	      // create new tun setup object
	      tun_setup = config->new_setup_obj();

	      // create config object for tun setup layer
	      Setup::Config tsconf;
	      tsconf.iface_name = state->iface_name;
	      tsconf.layer = config->layer;

	      // open/config tun
	      int fd = -1;
	      {
		std::ostringstream os;
		auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });
		fd = tun_setup->establish(*po, &tsconf, config->stop, os);
	      }

	      // create ASIO wrapper for tun fd
	      tun_wrap->save_replace_sock(new TUNStream(io_context, fd));

	      // enable tun_setup destructor
	      tun_wrap->add_destructor(tun_setup);

	      // configure tun interface packet forwarding
	      impl.reset(new TunImpl(tun_wrap,
				     tsconf.iface_name,
				     true,
				     tsconf.tun_prefix,
				     this,
				     config->frame,
				     config->stats
				     ));
	      impl->start(config->n_parallel);

	      // signal that we are connected
	      parent.tun_connected();
	    }
	    catch (const std::exception& e)
	      {
		if (tun_wrap)
		  tun_wrap->close();
		stop();
		Error::Type err = Error::TUN_SETUP_FAILED;
		const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
		if (ec && ec->code_defined())
		  err = ec->code();
		parent.tun_error(err, e.what());
	      }
	  }
      }

      virtual bool tun_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual std::string tun_name() const
      {
	if (impl)
	  return impl->name();
	else
	  return "UNDEF_TUN";
      }

      virtual std::string vpn_ip4() const
      {
	if (state->vpn_ip4_addr.specified())
	  return state->vpn_ip4_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_ip6() const
      {
	if (state->vpn_ip6_addr.specified())
	  return state->vpn_ip6_addr.to_string();
	else
	  return "";
      }

      virtual void set_disconnect()
      {
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(asio::io_context& io_context_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_context(io_context_arg),
	   config(config_arg),
	   parent(parent_arg),
	   halt(false),
	   state(new TunProp::State())
      {
      }

      bool send(Buffer& buf)
      {
	if (impl)
	  return impl->write(buf);
	else
	  return false;
      }

      void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
      {
	parent.tun_recv(pfp->buf);
      }

      void tun_error_handler(const Error::Type errtype, // called by TunImpl
			     const asio::error_code* error)
      {
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // stop tun
	    if (impl)
	      impl->stop();
	    tun_wrap.reset();
	  }
      }

      asio::io_context& io_context;
      TunWrap::Ptr tun_wrap; // contains the tun device fd
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      TunProp::State::Ptr state;
      TunBuilderSetup::Base::Ptr tun_setup;
    };

    inline TunClient::Ptr ClientConfig::new_tun_client_obj(asio::io_context& io_context,
							   TunClientParent& parent,
							   TransportClient* transcli)
    {
      return TunClient::Ptr(new Client(io_context, this, parent));
    }

  }
} // namespace openvpn

#endif
