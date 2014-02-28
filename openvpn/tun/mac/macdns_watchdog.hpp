//
//  macdns_watchdog.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// DNS utilities for Mac

#ifndef OPENVPN_TUN_MAC_MACDNS_WATCHDOG_H
#define OPENVPN_TUN_MAC_MACDNS_WATCHDOG_H

#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/tun/mac/macdns.hpp>

namespace openvpn {
  class MacDNSWatchdog : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<MacDNSWatchdog> Ptr;

    static void add_actions(boost::asio::io_service& io_service,
			    const TunBuilderCapture& settings,
			    const std::string& sname,
			    ActionList& create,
			    ActionList& destroy)
    {
      MacDNSWatchdog::Ptr watchdog(new MacDNSWatchdog(io_service, settings, sname));
      DNSAction::Ptr create_action(new DNSAction(true, watchdog));
      DNSAction::Ptr destroy_action(new DNSAction(false, watchdog));
      create.add(create_action);
      destroy.add(destroy_action);
    }

  private:
    class DNSAction : public Action
    {
    public:
      typedef boost::intrusive_ptr<DNSAction> Ptr;

      DNSAction(const bool state_arg, const MacDNSWatchdog::Ptr& parent_arg)
	: state(state_arg),
	  parent(parent_arg)
      {
      }

      virtual void execute()
      {
	OPENVPN_LOG(to_string());
	if (parent)
	  parent->setdns(state);
      }

      virtual std::string to_string() const
      {
	std::ostringstream os;
	os << "MacDNS: ";
	if (state)
	  os << "setdns ";
	else
	  os << "resetdns ";
	if (parent)
	  os << parent->to_string();
	else
	  os << "UNDEF";
	return os.str();
      }

    private:
      bool state;
      MacDNSWatchdog::Ptr parent;
    };

    MacDNSWatchdog(boost::asio::io_service& io_service_arg,
		   const TunBuilderCapture& settings,
		   const std::string& sname)
      : halt(false),
	io_service(io_service_arg),
	config(new MacDNS::Config(settings)),
	macdns(new MacDNS(sname)),
	watchdog_timer(io_service_arg)
    {
    }

    bool setdns(const bool state)
    {
      bool mod = false;
      if (!halt && macdns && config)
	{
	  if (state)
	    mod = macdns->setdns(*config);
	  else
	    mod = macdns->resetdns();
	  if (mod)
	    {
	      macdns->flush_cache();
	      macdns->signal_network_reconfiguration();
	    }
	}
      return mod;
    }

    std::string to_string() const
    {
      if (!halt && config)
	return config->to_string();
      else
	return std::string("UNDEF");
    }

    bool halt;
    boost::asio::io_service& io_service;
    MacDNS::Config::Ptr config;
    MacDNS::Ptr macdns;
    AsioTimer watchdog_timer;
  };
}

#endif
