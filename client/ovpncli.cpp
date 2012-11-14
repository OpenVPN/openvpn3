//
//  ovpncli.cpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// OpenVPN client ("OpenVPNClient" class) intended to be wrapped by swig
// for a target language.

#include <iostream>

// Set up export of our public interface unless
// OPENVPN_CORE_API_VISIBILITY_HIDDEN is defined
#if defined(__GNUC__)
#define OPENVPN_CLIENT_EXPORT
#ifndef OPENVPN_CORE_API_VISIBILITY_HIDDEN
#pragma GCC visibility push(default)
#endif
#include "ovpncli.hpp" // public interface
#ifndef OPENVPN_CORE_API_VISIBILITY_HIDDEN
#pragma GCC visibility pop
#endif
#else
#error no public interface export defined for this compiler
#endif

// debug settings

#define OPENVPN_DEBUG
//#define OPENVPN_ENABLE_ASSERT
//#define OPENVPN_SSL_DEBUG
//#define OPENVPN_DEBUG_CLIPROTO
//#define OPENVPN_FORCE_TUN_NULL
#define OPENVPN_DEBUG_PROTO
#define OPENVPN_DEBUG_TUN     2
#define OPENVPN_DEBUG_UDPLINK 2
#define OPENVPN_DEBUG_TCPLINK 2
#define OPENVPN_DEBUG_COMPRESS 1
//#define OPENVPN_DEBUG_PACKET_ID
//#define OPENVPN_PACKET_LOG "pkt.log"

// log thread settings
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::OpenVPNClient
#define OPENVPN_LOG_INFO  openvpn::ClientAPI::LogInfo

// log SSL handshake messages
#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

// on Android and iOS, use TunBuilderBase abstraction
#include <openvpn/common/platform.hpp>
#if (defined(OPENVPN_PLATFORM_ANDROID) || defined(OPENVPN_PLATFORM_IPHONE)) && !defined(OPENVPN_FORCE_TUN_NULL)
#define USE_TUN_BUILDER
#endif

#include <openvpn/log/logthread.hpp>    // should be included early

#include <openvpn/init/initprocess.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/client/cliconnect.hpp>
#include <openvpn/options/cliopthelper.hpp>
#include <openvpn/options/merge.hpp>

// copyright
#include <openvpn/legal/copyright.hpp>

namespace openvpn {
  namespace ClientAPI {

    OPENVPN_SIMPLE_EXCEPTION(app_expired);

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

      count_t stat_count(const size_t index) const
      {
	return get_stat_fast(index);
      }

      count_t error_count(const size_t index) const
      {
	return errors[index];
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

      virtual void error(const size_t err, const std::string* text=NULL)
      {
	if (err < Error::N_ERRORS)
	  ++errors[err];
      }

    private:
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
	    ev.info = Unicode::utf8_printable(event->render(), 256);
	    ev.error = event->is_error();

	    // save connected event
	    if (event->id() == ClientEvent::CONNECTED)
	      last_connected = event;

	    parent->event(ev);
	  }
      }

      void get_connection_info(ConnectionInfo& ci)
      {
	ClientEvent::Base::Ptr connected = last_connected;
	if (connected)
	  {
	    const ClientEvent::Connected* c = connected->connected_cast();
	    if (c)
	      {
		ci.user = c->user;
		ci.serverHost = c->server_host;
		ci.serverPort = c->server_port;
		ci.serverProto = c->server_proto;
		ci.serverIp = c->server_ip;
		ci.vpnIp4 = c->vpn_ip4;
		ci.vpnIp6 = c->vpn_ip6;
		ci.clientIp = c->client_ip;
		ci.tunName = c->tun_name;
		ci.defined = true;
		return;
	      }
	  }
	ci.defined = false;
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

    private:
      OpenVPNClient* parent;
      ClientEvent::Base::Ptr last_connected;
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

    class MyReconnectNotify : public ReconnectNotify
    {
    public:
      MyReconnectNotify() : parent(NULL) {}

      void set_parent(OpenVPNClient* parent_arg)
      {
	parent = parent_arg;
      }

      void detach_from_parent()
      {
	parent = NULL;
      }

      virtual bool pause_on_connection_timeout()
      {
	if (parent)
	  return parent->pause_on_connection_timeout();
	else
	  return false;
      }

    private:
      OpenVPNClient* parent;
    };

    namespace Private {
      struct ClientState
      {
	ClientState() : conn_timeout(0), tun_persist(false), google_dns_fallback(false) {}

	OptionList options;
	EvalConfig eval;
	MySocketProtect socket_protect;
	MyReconnectNotify reconnect_notify;
	ClientCreds::Ptr creds;
	MySessionStats::Ptr stats;
	MyClientEvents::Ptr events;
	ClientConnect::Ptr session;

	// extra settings submitted by API client
	std::string server_override;
	Protocol proto_override;
	int conn_timeout;
	bool tun_persist;
	bool google_dns_fallback;
	std::string external_pki_alias;
	ProtoContextOptions::Ptr proto_context_options;
	HTTPProxyTransport::Options::Ptr http_proxy_options;
      };
    };

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::init_process()
    {
      InitProcess::init();
    }

    OPENVPN_CLIENT_EXPORT OpenVPNClient::OpenVPNClient()
    {
      // We keep track of time as binary milliseconds since a time base, and
      // this can wrap after ~48 days on 32 bit systems, so it's a good idea
      // to periodically reinitialize the base.
      Time::reset_base_conditional();

      state = new Private::ClientState();
      state->proto_context_options = new ProtoContextOptions();
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::parse_config(const Config& config, EvalConfig& eval, OptionList& options)
    {
      try {
	// validate proto_override
	if (!config.protoOverride.empty())
	  Protocol::parse(config.protoOverride);

	// parse config
	OptionList::KeyValueList kvl;
	kvl.reserve(config.contentList.size());
	for (size_t i = 0; i < config.contentList.size(); ++i)
	  {
	    const KeyValue& kv = config.contentList[i];
	    kvl.push_back(new OptionList::KeyValue(kv.key, kv.value));
	  }
	const ParseClientConfig cc = ParseClientConfig::parse(config.content, &kvl, options);
	eval.error = cc.error();
	eval.message = cc.message();
	eval.userlockedUsername = cc.userlockedUsername();
	eval.profileName = cc.profileName();
	eval.friendlyName = cc.friendlyName();
	eval.autologin = cc.autologin();
	eval.externalPki = cc.externalPki();
	eval.staticChallenge = cc.staticChallenge();
	eval.staticChallengeEcho = cc.staticChallengeEcho();
	for (ParseClientConfig::ServerList::const_iterator i = cc.serverList().begin(); i != cc.serverList().end(); ++i)
	  {
	    ServerEntry se;
	    se.server = i->server;
	    se.friendlyName = i->friendlyName;
	    eval.serverList.push_back(se);
	  }
      }
      catch (const std::exception& e)
	{
	  eval.error = true;
	  eval.message = Unicode::utf8_printable(e.what(), 256);
	}
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::parse_extras(const Config& config, EvalConfig& eval)
    {
      try {
	state->server_override = config.serverOverride;
	state->conn_timeout = config.connTimeout;
	state->tun_persist = config.tunPersist;
	state->google_dns_fallback = config.googleDnsFallback;
	if (!config.protoOverride.empty())
	  state->proto_override = Protocol::parse(config.protoOverride);
	if (!config.compressionMode.empty())
	  state->proto_context_options->parse_compression_mode(config.compressionMode);
	if (eval.externalPki)
	  state->external_pki_alias = config.externalPkiAlias;
	if (!config.proxyHost.empty())
	  {
	    HTTPProxyTransport::Options::Ptr ho(new HTTPProxyTransport::Options());
	    ho->host = config.proxyHost;
	    ho->port = config.proxyPort;
	    ho->username = config.proxyUsername;
	    ho->password = config.proxyPassword;
	    ho->allow_cleartext_auth = config.proxyAllowCleartextAuth;
	    ho->validate();
	    state->http_proxy_options = ho;
	  }
      }
      catch (const std::exception& e)
	{
	  eval.error = true;
	  eval.message = Unicode::utf8_printable(e.what(), 256);
	}
    }


    OPENVPN_CLIENT_EXPORT long OpenVPNClient::max_profile_size()
    {
      return ProfileParseLimits::MAX_PROFILE_SIZE;
    }

    OPENVPN_CLIENT_EXPORT MergeConfig OpenVPNClient::merge_config_static(const std::string& path,
									 bool follow_references)
    {
      ProfileMerge pm(path, "", follow_references,
		      ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
      return build_merge_config(pm);
    }

    OPENVPN_CLIENT_EXPORT MergeConfig OpenVPNClient::merge_config_string_static(const std::string& config_content)
    {
      ProfileMergeFromString pm(config_content, "", false,
				ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
      return build_merge_config(pm);
    }

    OPENVPN_CLIENT_EXPORT MergeConfig OpenVPNClient::build_merge_config(const ProfileMerge& pm)
    {
      MergeConfig ret;
      ret.status = pm.status_string();
      ret.basename = pm.basename();
      if (pm.status() == ProfileMerge::MERGE_SUCCESS)
	{
	  ret.refPathList = pm.ref_path_list();
	  ret.profileContent = pm.profile_content();
	}
      else
	{
	  ret.errorText = pm.error();
	}
      return ret;
    }

    OPENVPN_CLIENT_EXPORT EvalConfig OpenVPNClient::eval_config_static(const Config& config)
    {
      EvalConfig eval;
      OptionList options;
      parse_config(config, eval, options);
      return eval;
    }

    // API client submits the configuration here before calling connect()
    OPENVPN_CLIENT_EXPORT EvalConfig OpenVPNClient::eval_config(const Config& config)
    {
      // parse and validate configuration file
      EvalConfig eval;
      parse_config(config, eval, state->options);
      if (eval.error)
	return eval;

      // handle extra settings in config
      parse_extras(config, eval);
      state->eval = eval;
      return eval;      
    }

    OPENVPN_CLIENT_EXPORT Status OpenVPNClient::provide_creds(const ProvideCreds& creds)
    {
      Status ret;
      try {
	ClientCreds::Ptr cc = new ClientCreds();
	cc->set_username(creds.username);
	cc->set_password(creds.password);
	cc->set_response(creds.response);
	cc->set_dynamic_challenge_cookie(creds.dynamicChallengeCookie);
	cc->set_replace_password_with_session_id(creds.replacePasswordWithSessionID);
	state->creds = cc;
      }
      catch (const std::exception& e)
	{
	  ret.error = true;
	  ret.message = Unicode::utf8_printable(e.what(), 256);
	}
      return ret;
    }

    OPENVPN_CLIENT_EXPORT bool OpenVPNClient::parse_dynamic_challenge(const std::string& cookie, DynamicChallenge& dc)
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

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::process_epki_cert_chain(const ExternalPKICertRequest& req)
    {
      // Get cert and add to options list
      {
	Option o;
	o.push_back("cert");
	o.push_back(req.cert);
	state->options.add_item(o);
      }
      
      // Get the supporting chain, if it exists, and use
      // it for ca (if ca isn't defined), or otherwise use
      // it for extra-certs (if ca is defined but extra-certs
      // is not).
      if (!req.supportingChain.empty())
	{
	  if (!state->options.exists("ca"))
	    {
	      Option o;
	      o.push_back("ca");
	      o.push_back(req.supportingChain);
	      state->options.add_item(o);
	    }
	  else if (!state->options.exists("extra-certs"))
	    {
	      Option o;
	      o.push_back("extra-certs");
	      o.push_back(req.supportingChain);
	      state->options.add_item(o);
	    }
	}
    }

    OPENVPN_CLIENT_EXPORT Status OpenVPNClient::connect()
    {
      boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
      Log::Context log_context(this);
      Status ret;
      bool in_run = false;
      ScopedPtr<boost::asio::io_service> io_service;

      // client stats
      state->stats.reset(new MySessionStats(this));

      // client events
      state->events.reset(new MyClientEvents(this));

      // socket protect
      state->socket_protect.set_parent(this);

      // reconnect notifications
      state->reconnect_notify.set_parent(this);

      // session
      state->session.reset();

      try {
	// load options
	ClientOptions::Config cc;
	cc.cli_stats = state->stats;
	cc.cli_events = state->events;
	cc.server_override = state->server_override;
	cc.proto_override = state->proto_override;
	cc.conn_timeout = state->conn_timeout;
	cc.tun_persist = state->tun_persist;
	cc.google_dns_fallback = state->google_dns_fallback;
	cc.proto_context_options = state->proto_context_options;
	cc.http_proxy_options = state->http_proxy_options;
	cc.reconnect_notify = &state->reconnect_notify;
#if defined(USE_TUN_BUILDER)
	cc.socket_protect = &state->socket_protect;
	cc.builder = this;
#endif

	// external PKI
#if !defined(USE_APPLE_SSL)
	if (state->eval.externalPki)
	  {
	    if (!state->external_pki_alias.empty())
	      {
		ExternalPKICertRequest req;
		req.alias = state->external_pki_alias;
		external_pki_cert_request(req);
		if (!req.error)
		  {
		    cc.external_pki = this;
		    process_epki_cert_chain(req);
		  }
		else
		  {
		    external_pki_error(req, Error::EPKI_CERT_ERROR);
		    return ret;
		  }
	      }
	    else
	      {
		ret.error = true;
		ret.message = "Missing External PKI alias";
		return ret;
	      }
	  }
#endif

	// build client options object
	ClientOptions::Ptr client_options = new ClientOptions(state->options, cc);

	// configure creds in options
	client_options->submit_creds(state->creds);

	// initialize the Asio io_service object
	io_service.reset(new boost::asio::io_service(1)); // concurrency hint=1

	// instantiate top-level client session
	state->session.reset(new ClientConnect(*io_service, client_options));

	// raise an exception if app has expired
	check_app_expired();

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
	  ret.message = Unicode::utf8_printable(e.what(), 256);
	}
      state->socket_protect.detach_from_parent();
      state->reconnect_notify.detach_from_parent();
      state->stats->detach_from_parent();
      state->events->detach_from_parent();
      if (state->session)
	state->session.reset();
      return ret;
    }

    OPENVPN_CLIENT_EXPORT ConnectionInfo OpenVPNClient::connection_info()
    {
      ConnectionInfo ci;
      MyClientEvents::Ptr events = state->events;
      if (events)
	events->get_connection_info(ci);
      return ci;
    }

    OPENVPN_CLIENT_EXPORT bool OpenVPNClient::session_token(SessionToken& tok)
    {
      ClientCreds::Ptr cc = state->creds;
      if (cc && cc->session_id_defined())
	{
	  tok.username = cc->get_username();
	  tok.session_id = cc->get_password();
	  return true;
	}
      else
	return false;
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::external_pki_error(const ExternalPKIRequestBase& req, const size_t err_type)
    {
      if (req.error)
	{
	  if (req.invalidAlias)
	    {
	      ClientEvent::Base::Ptr ev = new ClientEvent::EpkiInvalidAlias(req.alias);
	      state->events->add_event(ev);
	    }

	  ClientEvent::Base::Ptr ev = new ClientEvent::EpkiError(req.errorText);
	  state->events->add_event(ev);

	  state->stats->error(err_type);
	  if (state->session)
	    state->session->dont_restart();
	}
    }

    OPENVPN_CLIENT_EXPORT bool OpenVPNClient::sign(const std::string& data, std::string& sig)
    {
      ExternalPKISignRequest req;
      req.data = data;
      req.alias = state->external_pki_alias;
      external_pki_sign_request(req); // call out to derived class for RSA signature
      if (!req.error)
	{
	  sig = req.sig;
	  return true;
	}
      else
	{
	  external_pki_error(req, Error::EPKI_SIGN_ERROR);
	  return false;
	}
    }

    OPENVPN_CLIENT_EXPORT int OpenVPNClient::stats_n()
    {
      return MySessionStats::combined_n();
    }

    OPENVPN_CLIENT_EXPORT std::string OpenVPNClient::stats_name(int index)
    {
      return MySessionStats::combined_name(index);
    }

    OPENVPN_CLIENT_EXPORT long long OpenVPNClient::stats_value(int index) const
    {
      MySessionStats::Ptr stats = state->stats;
      if (stats)
	return stats->combined_value(index);
      else
	return 0;
    }

    OPENVPN_CLIENT_EXPORT std::vector<long long> OpenVPNClient::stats_bundle() const
    {
      std::vector<long long> sv;
      MySessionStats::Ptr stats = state->stats;
      const size_t n = MySessionStats::combined_n();
      sv.reserve(n);
      for (size_t i = 0; i < n; ++i)
	sv.push_back(stats ? stats->combined_value(i) : 0);
      return sv;
    }

    OPENVPN_CLIENT_EXPORT InterfaceStats OpenVPNClient::tun_stats() const
    {
      MySessionStats::Ptr stats = state->stats;
      InterfaceStats ret;

      // The reason for the apparent inversion between in/out below is
      // that TUN_*_OUT stats refer to data written to tun device,
      // but from the perspective of tun interface, this is incoming
      // data.  Vice versa for TUN_*_IN.
      if (stats)
	{
	  ret.bytesOut = stats->stat_count(SessionStats::TUN_BYTES_IN);
	  ret.bytesIn = stats->stat_count(SessionStats::TUN_BYTES_OUT);
	  ret.packetsOut = stats->stat_count(SessionStats::TUN_PACKETS_IN);
	  ret.packetsIn = stats->stat_count(SessionStats::TUN_PACKETS_OUT);
	  ret.errorsOut = stats->error_count(Error::TUN_READ_ERROR);
	  ret.errorsIn = stats->error_count(Error::TUN_WRITE_ERROR);
	}
      else
	{
	  ret.bytesOut = 0;
	  ret.bytesIn = 0;
	  ret.packetsOut = 0;
	  ret.packetsIn = 0;
	  ret.errorsOut = 0;
	  ret.errorsIn = 0;
	}
      return ret;
    }

    OPENVPN_CLIENT_EXPORT TransportStats OpenVPNClient::transport_stats() const
    {
      MySessionStats::Ptr stats = state->stats;
      TransportStats ret;

      ret.lastPacketReceived = -1; // undefined
      if (stats)
	{
	  ret.bytesOut = stats->stat_count(SessionStats::BYTES_OUT);
	  ret.bytesIn = stats->stat_count(SessionStats::BYTES_IN);
	  ret.packetsOut = stats->stat_count(SessionStats::PACKETS_OUT);
	  ret.packetsIn = stats->stat_count(SessionStats::PACKETS_IN);

	  // calculate time since last packet received
	  {
	    const Time& lpr = stats->last_packet_received();
	    if (lpr.defined())
	      {
		const Time::Duration dur = Time::now() - lpr;
		const unsigned int delta = dur.to_binary_ms();
		if (delta <= 60*60*24*1024) // only define for time periods <= 1 day
		  ret.lastPacketReceived = delta;
	      }
	  }
	}
      else
	{
	  ret.bytesOut = 0;
	  ret.bytesIn = 0;
	  ret.packetsOut = 0;
	  ret.packetsIn = 0;
	}
      return ret;
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::stop()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_stop();
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::pause()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_pause();
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::resume()
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_resume();
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::reconnect(int seconds)
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_reconnect(seconds);
    }

    OPENVPN_CLIENT_EXPORT int OpenVPNClient::app_expire()
    {
#ifdef APP_EXPIRE_TIME
      return APP_EXPIRE_TIME;
#else
      return 0;
#endif
    }

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::check_app_expired()
    {
#ifdef APP_EXPIRE_TIME
      if (Time::now().seconds_since_epoch() >= APP_EXPIRE_TIME)
	throw app_expired();
#endif
    }

    OPENVPN_CLIENT_EXPORT std::string OpenVPNClient::copyright()
    {
      return openvpn_copyright;
    }

    OPENVPN_CLIENT_EXPORT OpenVPNClient::~OpenVPNClient()
    {
      delete state;
    }

    OPENVPN_CLIENT_EXPORT LogInfo::LogInfo(const std::string& str)
      : text(Unicode::utf8_printable(str, 4096 | Unicode::UTF8_PASS_FMT)) {}
  }
}
