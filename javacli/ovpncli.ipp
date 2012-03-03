// OpenVPN client ("OpenVPNClient" class) intended to be wrapped by swig
// for a target language.

#include <iostream>

#include "ovpncli.hpp" // objects that we bridge with wrapping language

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
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::OpenVPNClient
#define OPENVPN_LOG_INFO  openvpn::ClientAPI::LogInfo

// on Android, use TunBuilderBase abstraction
#include <openvpn/common/platform.hpp>
#if defined(OPENVPN_PLATFORM_ANDROID) && !defined(OPENVPN_FORCE_TUN_NULL)
#define USE_TUN_BUILDER
#endif

#include <openvpn/log/logthread.hpp>    // should be included early

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

      MySessionStats(OpenVPNClient* parent_arg)
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

      OpenVPNClient* parent;
      count_t errors[Error::N_ERRORS];
    };

    class MyClientEvents : public ClientEvent::Queue
    {
    public:
      typedef boost::intrusive_ptr<MyClientEvents> Ptr;

      MyClientEvents(OpenVPNClient* parent_arg) : parent(parent_arg) {}

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
      OpenVPNClient* parent;
    };

    class MySocketProtect : public SocketProtect
    {
    public:
      MySocketProtect() : parent(NULL) {}

      void set_parent(OpenVPNClient* parent_arg)
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
      OpenVPNClient* parent;
    };

    namespace Private {
      struct ClientState
      {
	OptionList options;
	MySocketProtect socket_protect;
	ClientCreds::Ptr creds;
	MySessionStats::Ptr stats;
	MyClientEvents::Ptr events;
	ClientConnect::Ptr session;
      };
    };

    inline OpenVPNClient::OpenVPNClient()
    {
      InitProcess::init();
      state = new Private::ClientState();
    }

    inline void OpenVPNClient::parse_config(const Config& config, EvalConfig& eval, OptionList& options)
    {
      try {
	// parse config
	options.parse_from_config(config.content);
	options.parse_meta_from_config(config.content, "OVPN_ACCESS_SERVER");
	options.update_map();

	// fill out EvalConfig struct

	// userlocked username
	{
	  const Option *o = options.get_ptr("USERNAME");
	  if (o)
	    eval.userlockedUsername = o->get(1);
	}

	// autologin
	{
	  const Option *o = options.get_ptr("auth-user-pass");
	  eval.autologin = !o;
	  if (eval.autologin)
	    {
	      o = options.get_ptr("EXTERNAL_PKI");
	      if (o)
		{
		  if (o->get(1) == "1")
		    eval.autologin = false;
		}
	    }
	}

	// static challenge
	{
	  const Option *o = options.get_ptr("static-challenge");
	  if (o)
	    {
	      eval.staticChallenge = o->get(1);
	      if (o->get_optional(2) == "1")
		eval.staticChallengeEcho = true;
	    }
	}

	// profile name
	{
	  const Option *o = options.get_ptr("PROFILE");
	  if (o)
	    eval.profileName = o->get(1);
	  else
	    {
	      RemoteList rl(options);
	      if (rl.size() >= 1)
		eval.profileName = rl[0].server_host;
	    }
	}

	// friendly name
	{
	  const Option *o = options.get_ptr("FRIENDLY_NAME");
	  if (o)
	    eval.friendlyName = o->get(1);
	}

	// server list
	{
	  const Option *o = options.get_ptr("HOST_LIST");
	  if (o)
	    {
	      std::stringstream in(o->get(1));
	      std::string line;
	      while (std::getline(in, line))
		{
		  ServerEntry se;
		  se.server = line;
		  eval.serverList.push_back(se);
		}
	    }
	}
      }
      catch (const std::exception& e)
	{
	  eval.error = true;
	  eval.message = e.what();
	}
    }

    inline EvalConfig OpenVPNClient::eval_config_static(const Config& config)
    {
      EvalConfig eval;
      OptionList options;
      parse_config(config, eval, options);
      return eval;
    }

    inline EvalConfig OpenVPNClient::eval_config(const Config& config) const
    {
      EvalConfig eval;
      state->options.clear();
      parse_config(config, eval, state->options);
      return eval;      
    }

    inline Status OpenVPNClient::provide_creds(const ProvideCreds& creds)
    {
      Status ret;
      try {
	ClientCreds::Ptr cc = new ClientCreds();
	cc->set_username(creds.username);
	cc->set_password(creds.password);
	cc->set_response(creds.response);
	cc->set_server_override(creds.serverOverride);
	cc->set_proto_override(creds.protoOverride);
	cc->set_dynamic_challenge_cookie(creds.dynamicChallengeCookie);
	cc->set_replace_password_with_session_id(creds.replacePasswordWithSessionID);
	state->creds = cc;
      }
      catch (const std::exception& e)
	{
	  ret.error = true;
	  ret.message = e.what();
	}
      return ret;
    }

    inline bool OpenVPNClient::parse_dynamic_challenge(const std::string& cookie, DynamicChallenge& dc)
    {
      try {
	ChallengeResponse cr(cookie);
	dc.challenge = cr.get_challenge_text();
	dc.echo = cr.get_echo();
	dc.responseRequired = cr.get_response_required();
	return true;
      }
      catch (const std::exception&)
	{
	  return false;
	}
    }


    inline Status OpenVPNClient::connect()
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
	ClientOptions::Config cc;
	cc.cli_stats = state->stats;
	cc.cli_events = state->events;
#if defined(USE_TUN_BUILDER)
	cc.socket_protect = &state->socket_protect;
	cc.builder = this;
#endif
	ClientOptions::Ptr client_options = new ClientOptions(state->options, cc);

	// configure creds in options
	client_options->submit_creds(state->creds);

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

    inline int OpenVPNClient::stats_n()
    {
      return MySessionStats::combined_n();
    }

    inline std::string OpenVPNClient::stats_name(int index)
    {
      return MySessionStats::combined_name(index);
    }

    inline long long OpenVPNClient::stats_value(int index) const
    {
      MySessionStats::Ptr stats = state->stats;
      if (stats)
	return stats->combined_value(index);
      else
	return 0;
    }

    inline void OpenVPNClient::stop()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_stop();
    }

    inline void OpenVPNClient::pause()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_pause();
    }

    inline void OpenVPNClient::resume()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_resume();
    }

    inline void OpenVPNClient::reconnect(int seconds)
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_reconnect(seconds);
    }

    inline OpenVPNClient::~OpenVPNClient()
    {
      delete state;
    }
  }
}
