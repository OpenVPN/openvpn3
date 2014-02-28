//
//  tuncli.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// Client tun interface for Mac OS X

#ifndef OPENVPN_TUN_MAC_CLIENT_TUNCLI_H
#define OPENVPN_TUN_MAC_CLIENT_TUNCLI_H

#include <string>
#include <sstream>

#include <openvpn/common/format.hpp>
#include <openvpn/common/scoped_asio_stream.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunpersistasio.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/layer.hpp>
#include <openvpn/tun/mac/tunutil.hpp>
#include <openvpn/tun/mac/utun.hpp>
#include <openvpn/tun/mac/gwv4.hpp>
#include <openvpn/tun/mac/macdns_watchdog.hpp>

namespace openvpn {
  namespace TunMac {

    OPENVPN_EXCEPTION(tun_mac_error);

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // tun interface wrapper for Mac OS X
    template <typename ReadHandler, typename TunPersist>
    class Tun : public TunIO<ReadHandler, PacketFrom, TunPersistAsioStream<TunPersist> >
    {
      typedef TunIO<ReadHandler, PacketFrom, TunPersistAsioStream<TunPersist>  > Base;

    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(const typename TunPersist::Ptr& tun_persist,
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
	Base::stream = new TunPersistAsioStream<TunPersist>(tun_persist);
      }
    };

    // These types manage the underlying tun driver fd
    typedef boost::asio::posix::stream_descriptor TUNStream;
    typedef ScopedAsioStream<TUNStream> ScopedTUNStream;
    typedef TunPersistTemplate<ScopedTUNStream> TunPersist;

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      Layer layer;               // OSI layer

      TunProp::Config tun_prop;
      int n_parallel;            // number of parallel async reads on tun socket

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      TunPersist::Ptr tun_persist;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					    TunClientParent& parent);

      // called just prior to transmission of Disconnect event
      virtual void close_persistent()
      {
	tun_persist.reset();
      }

    private:
      ClientConfig() : n_parallel(8) {}
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, TunPersistAsioStream<TunPersist> >;  // calls tun_read_handler

      typedef Tun<Client*, TunPersist> TunImpl;

    public:
      virtual void client_start(const OptionList& opt, TransportClient& transcli)
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->tun_persist)
	      tun_persist = config->tun_persist; // long-term persistent
	    else
	      tun_persist.reset(new TunPersist(false, false, NULL)); // short-term

	    try {
	      bool tun_prefix = false;
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

		  // close old tun handle if persisted
		  tun_persist->close();

		  // parse pushed options
		  TunBuilderCapture::Ptr po(new TunBuilderCapture());
		  TunProp::configure_builder(po.get(),
					     state.get(),
					     config->stats.get(),
					     server_addr,
					     config->tun_prop,
					     opt,
					     false);

		  // handle MTU default
		  if (!po->mtu)
		    po->mtu = 1500;

		  OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string()); // fixme

		  // Open tun device.  Try Mac OS X integrated utun device first
		  // (layer 3 only), then fall back to TunTap third-party device.
		  // If successful, state->iface_name will be set to tun iface name.
		  int fd = -1;
		  try {
		    if (config->layer() == Layer::OSI_LAYER_3)
		      {
			try {
			  fd = UTun::utun_open(state->iface_name);
			  tun_prefix = true;
			}
			catch (const std::exception& e)
			  {
			    OPENVPN_LOG(e.what());
			  }
		      }
		    if (fd == -1)
		      fd = Util::tuntap_open(config->layer, state->iface_name);
		  }
		  catch (const std::exception& e)
		    {
		      parent.tun_error(Error::TUN_IFACE_CREATE, e.what());
		      return;
		    }

		  OPENVPN_LOG("open " << state->iface_name << " SUCCEEDED");

		  // create ASIO wrapper for tun fd
		  TUNStream* ts = new TUNStream(io_service, fd);

		  // persist state
		  if (tun_persist->persist_tun_state(ts, state))
		    OPENVPN_LOG("TunPersist: saving tun context:" << std::endl << tun_persist->options());

		  // configure adapter properties
		  ActionList::Ptr add_cmds = new ActionList();
		  remove_cmds.reset(new ActionList());
		  remove_cmds->enable_destroy(true);
		  tun_persist->add_destructor(remove_cmds);
		  tun_config(state->iface_name, *po, *add_cmds, *remove_cmds);
		  MacDNSWatchdog::add_actions(io_service, *po, "OpenVPNConnect", *add_cmds, *remove_cmds);
		  add_cmds->execute();
		}

	      impl.reset(new TunImpl(tun_persist,
				     state->iface_name,
				     true,
				     tun_prefix,
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
		parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
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

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_service(io_service_arg),
	   config(config_arg),
	   parent(parent_arg),
	   halt(false),
	   state(new TunProp::State())
      {
      }

      enum { // add_del_route flags
	R_IPv6=(1<<0),
	R_IFACE=(1<<1),
	R_ONLINK=(1<<2),
      };

      static void add_del_route(const std::string& addr_str,
				const int prefix_len,
				const std::string& gateway_str,
				const std::string& iface,
				const unsigned int flags,
				ActionList& create,
				ActionList& destroy)
      {
	if (flags & R_IPv6)
	  {
	    const IPv6::Addr addr = IPv6::Addr::from_string(addr_str);
	    const IPv6::Addr netmask = IPv6::Addr::netmask_from_prefix_len(prefix_len);
	    const IPv6::Addr net = addr & netmask;

	    Command::Ptr add(new Command);
	    add->argv.push_back("/sbin/route");
	    add->argv.push_back("add");
	    add->argv.push_back("-inet6");
	    add->argv.push_back(net.to_string());
	    add->argv.push_back("-prefixlen");
	    add->argv.push_back(to_string(prefix_len));
	    if ((flags & R_IFACE) && !iface.empty())
	      {
		add->argv.push_back("-iface");
		add->argv.push_back(iface);
	      }
	    else
	      add->argv.push_back(gateway_str);
	    create.add(add);

	    // for the destroy command, copy the add command but replace "add" with "delete"
	    Command::Ptr del(add->copy());
	    del->argv[1] = "delete";
	    destroy.add(del);
	  }
	else
	  {
	    const IPv4::Addr addr = IPv4::Addr::from_string(addr_str);
	    const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);
	    const IPv4::Addr net = addr & netmask;

	    Command::Ptr add(new Command);
	    add->argv.push_back("/sbin/route");
	    add->argv.push_back("add");
	    if (flags & R_ONLINK)
	      {
		add->argv.push_back("-cloning");
		add->argv.push_back("-net");
		add->argv.push_back(net.to_string());
		add->argv.push_back("-netmask");
		add->argv.push_back(netmask.to_string());
		add->argv.push_back("-interface");
		add->argv.push_back(iface);
	      }
	    else
	      {
		add->argv.push_back("-net");
		if ((flags & R_IFACE) && !iface.empty())
		  {
		    add->argv.push_back("-ifscope");
		    add->argv.push_back(iface);
		  }
		add->argv.push_back(net.to_string());
		add->argv.push_back(gateway_str);
		add->argv.push_back(netmask.to_string());
	      }
	    create.add(add);

	    // for the destroy command, copy the add command but replace "add" with "delete"
	    Command::Ptr del(add->copy());
	    del->argv[1] = "delete";
	    destroy.add(del);
	  }
      }

      static void tun_config(const std::string& iface_name,
			     const TunBuilderCapture& pull,
			     ActionList& create,
			     ActionList& destroy)
      {
	// get default gateway
	const MacGatewayInfoV4 gw;

	// set local4 and local6 to point to IPv4/6 route configurations
	const TunBuilderCapture::Route* local4 = NULL;
	const TunBuilderCapture::Route* local6 = NULL;
	if (pull.tunnel_address_index_ipv4 >= 0)
	  local4 = &pull.tunnel_addresses[pull.tunnel_address_index_ipv4];
	if (pull.tunnel_address_index_ipv6 >= 0)
	  local6 = &pull.tunnel_addresses[pull.tunnel_address_index_ipv6];

	// Set IPv4 Interface
	if (local4)
	  {
	    // Process ifconfig
	    const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(local4->prefix_length);
	    {
	      Command::Ptr cmd(new Command);
	      cmd->argv.push_back("/sbin/ifconfig");
	      cmd->argv.push_back(iface_name);
	      cmd->argv.push_back(local4->address);
	      cmd->argv.push_back(local4->address);
	      cmd->argv.push_back("netmask");
	      cmd->argv.push_back(netmask.to_string());
	      cmd->argv.push_back("mtu");
	      cmd->argv.push_back(to_string(pull.mtu));
	      cmd->argv.push_back("up");
	      create.add(cmd);
	    }
	    add_del_route(local4->address, local4->prefix_length, local4->address, iface_name, 0, create, destroy);
	  }

	// Set IPv6 Interface
	if (local6)
	  {
	    {
	      Command::Ptr cmd(new Command);
	      cmd->argv.push_back("/sbin/ifconfig");
	      cmd->argv.push_back(iface_name);
	      cmd->argv.push_back("inet6");
	      cmd->argv.push_back(local6->address + '/' + to_string(local6->prefix_length));
	      create.add(cmd);
	    }
	    add_del_route(local6->address, local6->prefix_length, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	  }

	// Process Routes
	{
	  for (std::vector<TunBuilderCapture::Route>::const_iterator i = pull.add_routes.begin(); i != pull.add_routes.end(); ++i)
	    {
	      const TunBuilderCapture::Route& route = *i;
	      if (route.ipv6)
		add_del_route(route.address, route.prefix_length, route.gateway, iface_name, R_IPv6, create, destroy);
	      else
		{
		  if (local4)
		    add_del_route(route.address, route.prefix_length, route.gateway, iface_name, 0, create, destroy);
		  else
		    throw tun_mac_error("IPv4 routes pushed without IPv4 ifconfig");
		}
	    }
	}

	// Process IPv4 redirect-gateway
	if (pull.reroute_gw.ipv4)
	  {
	    // add server bypass route
	    if (gw.iface_addr_defined())
	      {
		if (!pull.remote_address.ipv6)
		  {
		    add_del_route(pull.remote_address.address, 32, gw.gateway_addr_str(), gw.iface(), 0, create, destroy);
		    add_del_route(gw.gateway_addr_str(), 32, "", gw.iface(), R_ONLINK, create, destroy);
		  }
	      }
	    else
	      throw tun_mac_error("redirect-gateway error: cannot detect default gateway");

	    add_del_route("0.0.0.0", 1, local4->gateway, iface_name, 0, create, destroy);
	    add_del_route("128.0.0.0", 1, local4->gateway, iface_name, 0, create, destroy);
	  }

	// Process IPv6 redirect-gateway
	if (pull.reroute_gw.ipv6)
	  {
	    add_del_route("0000::", 1, local6->gateway, iface_name, R_IPv6, create, destroy);
	    add_del_route("8000::", 1, local6->gateway, iface_name, R_IPv6, create, destroy);
	  }

	// Process exclude routes
	if (!pull.exclude_routes.empty())
	  {
	    if (gw.iface_addr_defined())
	      {
		bool ipv6_error = false;
		for (std::vector<TunBuilderCapture::Route>::const_iterator i = pull.exclude_routes.begin(); i != pull.exclude_routes.end(); ++i)
		  {
		    const TunBuilderCapture::Route& route = *i;
		    if (route.ipv6)
		      ipv6_error = true;
		    else
		      add_del_route(route.address, route.prefix_length, gw.gateway_addr_str(), gw.iface(), 0, create, destroy);
		  }
		if (ipv6_error)
		  OPENVPN_LOG("NOTE: exclude IPv6 routes not currently supported");
	      }
	    else
	      OPENVPN_LOG("NOTE: exclude routes error: cannot detect default gateway");
	  }
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
			     const boost::system::error_code* error)
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
	    tun_persist.reset();
	  }
      }

      boost::asio::io_service& io_service;
      TunPersist::Ptr tun_persist; // contains the tun device fd
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      TunProp::State::Ptr state;
      ActionList::Ptr remove_cmds;
    };

    inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
						       TunClientParent& parent)
    {
      return TunClient::Ptr(new Client(io_service, this, parent));
    }

  }
} // namespace openvpn

#endif
