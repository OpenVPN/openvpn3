// OpenVPN client ("OpenVPNClientBase" class) intended for wrapping as a Java class using swig

#include <iostream>

#include "ovpncli.hpp" // objects that we bridge with java

// debug settings

#define OPENVPN_DEBUG
//#define OPENVPN_DEBUG_CLIPROTO
//#define OPENVPN_FORCE_TUN_NULL
//#define OPENVPN_DEBUG_PROTO
#define OPENVPN_DEBUG_TUN     2
#define OPENVPN_DEBUG_UDPLINK 2
#define OPENVPN_DEBUG_TCPLINK 2
//#define OPENVPN_DEBUG_COMPRESS
//#define OPENVPN_DEBUG_PACKET_ID
//#define OPENVPN_PACKET_LOG "pkt.log"

// log thread settings
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::OpenVPNClientBase
#define OPENVPN_LOG_INFO  openvpn::ClientAPI::LogInfo

// on Android, use TunBuilderBase abstraction
#if defined(OPENVPN_PLATFORM_ANDROID) && !defined(OPENVPN_FORCE_TUN_NULL)
#define USE_TUN_BUILDER
#endif

#include <openvpn/log/logthread.hpp>    // should be first included file from openvpn

#include <openvpn/init/initprocess.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/client/cliconnect.hpp>

namespace openvpn {
  namespace ClientAPI {

    class MySessionStats : public SessionStats
    {
    public:
      typedef boost::intrusive_ptr<MySessionStats> Ptr;

      MySessionStats(OpenVPNClientBase* parent_arg)
	: parent(parent_arg)
      {
	std::memset(errors, 0, sizeof(errors));
      }

      static size_t combined_n()
      {
	return N_STATS + Error::N_ERRORS;
      }

      static std::string combined_name(const size_t index)
      {
	if (index < N_STATS + Error::N_ERRORS)
	  {
	    if (index < N_STATS)
	      return stat_name(index);
	    else
	      return Error::name(index - N_STATS);
	  }
	else
	  return "";
      }

      count_t combined_value(const size_t index) const
      {
	if (index < N_STATS + Error::N_ERRORS)
	  {
	    if (index < N_STATS)
	      return get_stat(index);
	    else
	      return errors[index - N_STATS];
	  }
	else
	  return 0;
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

    private:
      virtual void error(const size_t err, const std::string* text=NULL)
      {
	if (err < Error::N_ERRORS)
	  ++errors[err];
      }

      OpenVPNClientBase* parent;
      count_t errors[Error::N_ERRORS];
    };

    class MyClientEvents : public ClientEvent::Queue
    {
    public:
      typedef boost::intrusive_ptr<MyClientEvents> Ptr;

      MyClientEvents(OpenVPNClientBase* parent_arg) : parent(parent_arg) {}

      virtual void add_event(const ClientEvent::Base::Ptr& event)
      {
	if (parent)
	  {
	    Event ev;
	    ev.name = event->name();
	    ev.info = event->render();
	    ev.error = event->is_error();
	    parent->event(ev);
	  }
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

    private:
      OpenVPNClientBase* parent;
    };

    class MySocketProtect : public SocketProtect
    {
    public:
      MySocketProtect() : parent(NULL) {}

      void set_parent(OpenVPNClientBase* parent_arg)
      {
	parent = parent_arg;
      }

      virtual bool socket_protect(int socket)
      {
	if (parent)
	  return parent->socket_protect(socket);
	else
	  return true;
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

    private:
      OpenVPNClientBase* parent;
    };

    namespace Private {
      struct ClientState
      {
	OptionList options;
	ProvideCreds creds;
	MySocketProtect socket_protect;
	MySessionStats::Ptr stats;
	MyClientEvents::Ptr events;
	ClientConnect::Ptr session;
      };
    };

    inline OpenVPNClientBase::OpenVPNClientBase()
    {
      InitProcess::init();
      state = new Private::ClientState();
    }

    inline void OpenVPNClientBase::parse_config(const Config& config, EvalConfig& eval, OptionList& options)
    {
      try {
	// parse config
	options.parse_from_config(config.content);
	options.update_map();

	// fill out RequestCreds struct
	{
	  const Option *o = options.get_ptr("auth-user-pass");
	  eval.autologin = !o;
	}
	{
	  const Option *o = options.get_ptr("static-challenge");
	  if (o)
	    {
	      eval.staticChallenge = o->get(1);
	      if (o->get(2) == "1")
		eval.staticChallengeEcho = true;
	    }
	}
      }
      catch (const std::exception& e)
	{
	  eval.error = true;
	  eval.message = e.what();
	}
    }

    EvalConfig OpenVPNClientBase::eval_config_static(const Config& config)
    {
      EvalConfig eval;
      OptionList options;
      parse_config(config, eval, options);
      return eval;
    }

    EvalConfig OpenVPNClientBase::eval_config(const Config& config) const
    {
      EvalConfig eval;
      state->options.clear();
      parse_config(config, eval, state->options);
      return eval;      
    }

    void OpenVPNClientBase::provide_creds(const ProvideCreds& creds)
    {
      state->creds = creds;
    }

    inline Status OpenVPNClientBase::connect()
    {
      boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
      Log::Context log_context(this);
      Status ret;
      bool in_run = false;
      ScopedPtr<boost::asio::io_service> io_service;

      try {
	// client stats
	state->stats.reset(new MySessionStats(this));

	// client events
	state->events.reset(new MyClientEvents(this));

	// socket protect
	state->socket_protect.set_parent(this);

	// load options
	ClientOptions::Ptr client_options = new ClientOptions(state->options, state->stats, state->events
#if defined(USE_TUN_BUILDER)
							      ,this
#endif
							      );

	// configure creds in options
	client_options->submit_creds(state->creds.username, state->creds.password);

	// initialize the Asio io_service object
	io_service.reset(new boost::asio::io_service(1)); // concurrency hint=1

	// instantiate top-level client session
	state->session.reset(new ClientConnect(*io_service, client_options));

	// start VPN
	state->session->start(); // queue parallel async reads

	// run i/o reactor
	in_run = true;	
	io_service->run();
      }
      catch (const std::exception& e)
	{
	  if (in_run)
	    {
	      state->session->stop(); // On exception, stop client...
	      io_service->poll();     //   and execute completion handlers.
	    }
	  ret.error = true;
	  ret.message = e.what();
	}
      state->socket_protect.detach_from_parent();
      state->stats->detach_from_parent();
      state->events->detach_from_parent();
      state->session.reset();
      return ret;
    }

    int OpenVPNClientBase::stats_n()
    {
      return MySessionStats::combined_n();
    }

    std::string OpenVPNClientBase::stats_name(int index)
    {
      return MySessionStats::combined_name(index);
    }

    long long OpenVPNClientBase::stats_value(int index) const
    {
      MySessionStats::Ptr stats = state->stats;
      if (stats)
	return stats->combined_value(index);
      else
	return 0;
    }

    inline void OpenVPNClientBase::stop()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_stop();
    }

    inline OpenVPNClientBase::~OpenVPNClientBase()
    {
      delete state;
    }
  }
}
