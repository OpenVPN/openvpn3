//
//  macdns_watchdog.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// DNS utilities for Mac

#ifndef OPENVPN_TUN_MAC_MACDNS_WATCHDOG_H
#define OPENVPN_TUN_MAC_MACDNS_WATCHDOG_H

#include <openvpn/common/thread.hpp>
#include <openvpn/log/logthread.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/applecrypto/cf/cftimer.hpp>
#include <openvpn/apple/runloop.hpp>
#include <openvpn/tun/mac/macdns.hpp>

namespace openvpn {
  OPENVPN_EXCEPTION(macdns_watchdog_error);

  class MacDNSWatchdog : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<MacDNSWatchdog> Ptr;

    static void add_actions(const TunBuilderCapture& settings,
			    const std::string& sname,
			    ActionList& create,
			    ActionList& destroy)
    {
      MacDNSWatchdog::Ptr watchdog(new MacDNSWatchdog(settings, sname));
      DNSAction::Ptr create_action(new DNSAction(true, watchdog));
      DNSAction::Ptr destroy_action(new DNSAction(false, watchdog));
      create.add(create_action);
      destroy.add(destroy_action);
    }

    virtual ~MacDNSWatchdog()
    {
      stop_thread();
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

    MacDNSWatchdog(const TunBuilderCapture& settings,
		   const std::string& sname)
      : config(new MacDNS::Config(settings)),
	macdns(new MacDNS(sname)),
	thread(NULL)
    {
    }

    bool setdns(const bool state)
    {
      bool mod = false;
      if (macdns && config)
	{
	  if (state)
	    {
	      if (!thread)
		{
		  mod = macdns->setdns(*config);
		  thread = new boost::thread(&MacDNSWatchdog::thread_func, this);
		}
	    }
	  else
	    {
	      stop_thread();
	      mod = macdns->resetdns();
	    }
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
      if (config)
	return config->to_string();
      else
	return std::string("UNDEF");
    }

    void stop_thread()
    {
      if (thread)
	{
	  if (runloop.defined())
	    CFRunLoopStop(runloop());
	  thread->join();
	  delete thread;
	  thread = NULL;
	}
    }

    // All methods below this point called in the context of watchdog thread.

    void thread_func()
    {
      runloop.reset(CFRunLoopGetCurrent(), CF::BORROW);
      Log::Context logctx(logwrap);

      try {
	SCDynamicStoreContext context = {0, this, NULL, NULL, NULL};
	CF::DynamicStore ds(SCDynamicStoreCreate(kCFAllocatorDefault,
						 CFSTR("OpenVPN_MacDNSWatchdog"),
						 callback_static,
						 &context));
	if (!ds.defined())
	  throw macdns_watchdog_error("SCDynamicStoreCreate");
	const CF::Array watched_keys(macdns->dskey_array());
	if (!watched_keys.defined())
	  throw macdns_watchdog_error("watched_keys is undefined");
	if (!SCDynamicStoreSetNotificationKeys(ds(),
					       watched_keys(),
					       NULL))
	  throw macdns_watchdog_error("SCDynamicStoreSetNotificationKeys failed");
	CF::RunLoopSource rls(SCDynamicStoreCreateRunLoopSource(kCFAllocatorDefault, ds(), 0));
	if (!rls.defined())
	  throw macdns_watchdog_error("SCDynamicStoreCreateRunLoopSource failed");
	CFRunLoopAddSource(CFRunLoopGetCurrent(), rls(), kCFRunLoopDefaultMode);

	// process event loop until CFRunLoopStop is called from parent thread
	CFRunLoopRun();
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("MacDNSWatchdog::thread_func: " << e.what());
	}
      cancel_push_timer();
    }

    static void callback_static(SCDynamicStoreRef store, CFArrayRef changedKeys, void *arg)
    {
      MacDNSWatchdog *self = (MacDNSWatchdog *)arg;
      self->callback(store, changedKeys);
    }

    void callback(SCDynamicStoreRef store, CFArrayRef changedKeys)
    {
      schedule_push_timer(3);
    }

    void schedule_push_timer(const int seconds)
    {
      CFRunLoopTimerContext context = { 0, this, NULL, NULL, NULL };
      cancel_push_timer();
      push_timer.reset(CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + seconds, 0, 0, 0, push_timer_callback_static, &context));
      if (push_timer.defined())
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), push_timer(), kCFRunLoopCommonModes);
      else
	OPENVPN_LOG("MacDNSWatchdog::schedule_push_timer: failed to create timer");
    }

    void cancel_push_timer()
    {
      if (push_timer.defined())
	{
	  CFRunLoopTimerInvalidate(push_timer());
	  push_timer.reset(NULL);
	}
    }

    static void push_timer_callback_static(CFRunLoopTimerRef timer, void *info)
    {
      MacDNSWatchdog* self = (MacDNSWatchdog*)info;
      self->push_timer_callback(timer);
    }

    void push_timer_callback(CFRunLoopTimerRef timer)
    {
      try {
	// reset DNS settings after watcher detected modifications by third party
	if (macdns->setdns(*config))
	  OPENVPN_LOG("MacDNSWatchdog: DNS watchdog triggered");
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("MacDNSWatchdog::push_timer_callback: " << e.what());
	}
    }

    MacDNS::Config::Ptr config;
    MacDNS::Ptr macdns;

    boost::thread* thread;         // watcher thread
    CF::RunLoop runloop;           // run loop in watcher thread
    CF::Timer push_timer;          // watcher thread timer
    Log::Context::Wrapper logwrap; // used to carry forward the log context from parent thread
  };
}

#endif
