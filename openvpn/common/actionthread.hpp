//
//  actionthread.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//


#ifndef OPENVPN_COMMON_ACTIONTHREAD_H
#define OPENVPN_COMMON_ACTIONTHREAD_H

#include <openvpn/common/rc.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/log/logthread.hpp>

namespace openvpn {

  class ActionThread : public RC<thread_safe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ActionThread> Ptr;

    struct Notify
    {
      virtual void action_thread_finished(const ActionThread* self, bool status) = 0;
    };

    ActionThread(boost::asio::io_service& io_service_arg,
		 const ActionList::Ptr& action_list,
		 Notify* completion_handler_arg)
      : io_service(io_service_arg),
	thread(NULL),
	actions(action_list),
	completion_handler(completion_handler_arg)
    {
      if (actions)
	thread = new boost::thread(&ActionThread::thread_func, this);
    }

    void stop(const bool halt)
    {
      if (thread)
	{
	  if (halt)
	    actions->halt();
	  thread->join();
	  delete thread;
	  thread = NULL;
	  // Necessary because no guarantee that completion_handler
	  // obj will remain in scope during io_service.post delay.
	  completion_handler = NULL;
	}
    }

    virtual ~ActionThread()
    {
      stop(true);
    }

  private:
    void completion_post(bool status)
    {
      Notify* n = completion_handler;
      completion_handler = NULL;
      if (n)
	n->action_thread_finished(this, status);
    }

    void thread_func()
    {
      Log::Context logctx(logwrap);
      bool status = false;
      try {
	OPENVPN_LOG("START THREAD...");
	status = actions->execute();
	OPENVPN_LOG("END THREAD");
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("ActionThread Exception: " << e.what());
	}
      io_service.post(asio_dispatch_post_arg(&ActionThread::completion_post, this, status));
    }

    boost::asio::io_service& io_service;
    boost::thread* thread;
    ActionList::Ptr actions;       // actions to execute in child thread
    Notify* completion_handler;    // completion handler
    Log::Context::Wrapper logwrap; // used to carry forward the log context from parent thread
  };

}

#endif
