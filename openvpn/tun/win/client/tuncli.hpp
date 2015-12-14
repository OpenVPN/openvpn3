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

// Client tun interface for Windows

#ifndef OPENVPN_TUN_WIN_CLIENT_TUNCLI_H
#define OPENVPN_TUN_WIN_CLIENT_TUNCLI_H

#include <string>
#include <sstream>
#include <memory>

#include <openvpn/common/format.hpp>
#include <openvpn/common/scoped_asio_stream.hpp>
#include <openvpn/common/cleanup.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunpersist.hpp>
#include <openvpn/tun/persist/tunwrapasio.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/win/client/tunsetup.hpp>

namespace openvpn {
  namespace TunWin {

    OPENVPN_EXCEPTION(tun_win_error);

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // tun interface wrapper for Windows
    template <typename ReadHandler, typename TunPersist>
    class Tun : public TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunPersist> >
    {
      typedef TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunPersist>  > Base;

    public:
      typedef RCPtr<Tun> Ptr;

      Tun(const typename TunPersist::Ptr& tun_persist,
	  const std::string& name,
	  const bool retain_stream,
	  ReadHandler read_handler,
	  const Frame::Ptr& frame,
	  const SessionStats::Ptr& stats)
	: Base(read_handler, frame, stats)
      {
	Base::name_ = name;
	Base::retain_stream = retain_stream;
	Base::stream = new TunWrapAsioStream<TunPersist>(tun_persist);
      }
    };

    // These types manage the underlying TAP driver HANDLE
    typedef asio::windows::stream_handle TAPStream;
    typedef ScopedAsioStream<TAPStream> ScopedTAPStream;
    typedef TunPersistTemplate<ScopedTAPStream> TunPersist;

    class ClientConfig : public TunClientFactory
    {
      friend class Client; // accesses wfp

    public:
      typedef RCPtr<ClientConfig> Ptr;

      TunProp::Config tun_prop;
      int n_parallel = 8;         // number of parallel async reads on tun socket

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      Stop* stop = nullptr;

      TunPersist::Ptr tun_persist;

      TunWin::SetupFactory::Ptr tun_setup_factory;

      TunWin::SetupBase::Ptr new_setup_obj(asio::io_context& io_context)
      {
	if (tun_setup_factory)
	  return tun_setup_factory->new_setup_obj(io_context);
	else
	  return new TunWin::Setup();
      }

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_tun_client_obj(asio::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);

      virtual void finalize(const bool disconnected)
      {
	if (disconnected)
	  tun_persist.reset();
      }
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, TunWrapAsioStream<TunPersist> >;  // calls tun_read_handler

      typedef Tun<Client*, TunPersist> TunImpl;

    public:
      typedef RCPtr<Client> Ptr;

      virtual void tun_start(const OptionList& opt, TransportClient& transcli, CryptoDCSettings&)
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->tun_persist)
	      tun_persist = config->tun_persist; // long-term persistent
	    else
	      tun_persist.reset(new TunPersist(false, false, nullptr)); // short-term

	    try {
	      const IP::Addr server_addr = transcli.server_endpoint_addr();

	      // Check if persisted tun session matches properties of to-be-created session
	      if (tun_persist->use_persisted_tun(server_addr, config->tun_prop, opt))
		{
		  state = tun_persist->state();
		  OPENVPN_LOG("TunPersist: reused tun context");
		}
	      else
		{
		  // notify parent
		  parent.tun_pre_tun_config();

		  // close old TAP handle if persisted
		  tun_persist->close();

		  // parse pushed options
		  TunBuilderCapture::Ptr po(new TunBuilderCapture());
		  TunProp::configure_builder(po.get(),
					     state.get(),
					     config->stats.get(),
					     server_addr,
					     config->tun_prop,
					     opt,
					     nullptr,
					     false);
		  OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string());

		  // create new tun setup object
		  TunWin::SetupBase::Ptr tun_setup(config->new_setup_obj(io_context));

		  // open/config TAP
		  HANDLE th;
		  {
		    std::ostringstream os;
		    auto os_print = Cleanup([&os](){ OPENVPN_LOG_STRING(os.str()); });
		    th = tun_setup->establish(*po, config->stop, os);
		  }

		  // create ASIO wrapper for HANDLE
		  TAPStream* ts = new TAPStream(io_context, th);

		  // assert ownership over TAP device handle
		  tun_setup->confirm();

		  // persist tun settings state
		  if (tun_persist->persist_tun_state(ts, state))
		    OPENVPN_LOG("TunPersist: saving tun context:" << std::endl << tun_persist->options());

		  // setup handler for external tun close
		  tun_setup->set_service_fail_handler([self=Ptr(this)]() {
		      if (!self->halt)
			self->parent.tun_error(Error::TUN_IFACE_DISABLED, "service failure");
		    });

		  // enable tun_setup destructor
		  tun_persist->add_destructor(tun_setup);
		}

	      // configure tun interface packet forwarding
	      impl.reset(new TunImpl(tun_persist,
				     "TUN_WIN",
				     true,
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
		if (tun_persist)
		  tun_persist->close();
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
#ifdef OPENVPN_DEBUG_TAPWIN
	tap_process_logging();
#endif
      }

      void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
      {
	parent.tun_recv(pfp->buf);
#ifdef OPENVPN_DEBUG_TAPWIN
	tap_process_logging();
#endif
      }

      void tun_error_handler(const Error::Type errtype, // called by TunImpl
			     const asio::error_code* error)
      {
	if (errtype == Error::TUN_READ_ERROR && error && error->value() == 995)
	  parent.tun_error(Error::TUN_IFACE_DISABLED, "TAP adapter is disabled");
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // stop tun
	    if (impl)
	      impl->stop();
	    tun_persist.reset();
	  }
      }

      HANDLE tap_handle()
      {
	if (tun_persist)
	  {
	    TAPStream* stream = tun_persist->obj();
	    if (stream)
	      return stream->native_handle();
	  }
	return Win::Handle::undefined();
      }

      void tap_process_logging()
      {
	HANDLE h = tap_handle();
	if (Win::Handle::defined(h))
	  Util::tap_process_logging(h);
      }

      asio::io_context& io_context;
      TunPersist::Ptr tun_persist; // contains the TAP device HANDLE
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      TunProp::State::Ptr state;
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
