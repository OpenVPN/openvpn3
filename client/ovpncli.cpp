//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Implementation file for OpenVPNClient API defined in ovpncli.hpp.

#include <iostream>
#include <string>

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
// no public interface export defined for this compiler
#define OPENVPN_CLIENT_EXPORT
#include "ovpncli.hpp" // public interface
#endif

// debug settings (production setting in parentheses)

#define OPENVPN_INSTRUMENTATION        // include debug instrumentation for classes (define)
//#define OPENVPN_DUMP_CONFIG          // dump parsed configuration (comment out)
//#define OPENVPN_DEBUG_CLIPROTO       // shows packets in/out (comment out)
#define OPENVPN_DEBUG_PROTO   1        // increases low-level protocol verbosity (1)
//#define OPENVPN_DEBUG_VERBOSE_ERRORS // verbosely log Error::Type errors (comment out)
#define OPENVPN_SSL_DEBUG     0        // show verbose SSL debug info (0)
#define OPENVPN_DEBUG_TUN     2        // debug level for tun object (2)
#define OPENVPN_DEBUG_UDPLINK 2        // debug level for UDP link object (2)
#define OPENVPN_DEBUG_TCPLINK 2        // debug level for TCP link object (2)
#define OPENVPN_DEBUG_COMPRESS 1       // debug level for compression objects (1)
#define OPENVPN_DEBUG_REMOTELIST 0     // debug level for RemoteList object (0)
#define OPENVPN_DEBUG_TUN_BUILDER 0    // debug level for tun/builder/client.hpp (0)
//#define OPENVPN_SHOW_SESSION_TOKEN   // show server-pushed auth-token (comment out)
//#define OPENVPN_DEBUG_TAPWIN           // shows Windows TAP driver debug logging (comment out)

// enable assertion checks (can safely be disabled in production)
//#define OPENVPN_ENABLE_ASSERT

// force null tun device (useful for testing)
//#define OPENVPN_FORCE_TUN_NULL

// log cleartext tunnel packets to file for debugging/analysis
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
#include <openvpn/common/platform_string.hpp>
#include <openvpn/client/cliconnect.hpp>
#include <openvpn/client/cliopthelper.hpp>
#include <openvpn/options/merge.hpp>
#include <openvpn/error/excode.hpp>
#include <openvpn/crypto/selftest.hpp>

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
#ifdef OPENVPN_DEBUG_VERBOSE_ERRORS
	session_stats_set_verbose(true);
#endif
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
	  {
#ifdef OPENVPN_DEBUG_VERBOSE_ERRORS
	    if (text)
	      OPENVPN_LOG("ERROR: " << Error::name(err) << " : " << *text);
	    else
	      OPENVPN_LOG("ERROR: " << Error::name(err));
#endif
	    ++errors[err];
	  }
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
	ClientState() : conn_timeout(0), tun_persist(false),
			google_dns_fallback(false), disable_client_cert(false),
			default_key_direction(-1), force_aes_cbc_ciphersuites(false) {}

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
	std::string private_key_password;
	std::string external_pki_alias;
	bool disable_client_cert;
	int default_key_direction;
	bool force_aes_cbc_ciphersuites;
	std::string gui_version;
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
	  Protocol::parse(config.protoOverride, false);

	// parse config
	OptionList::KeyValueList kvl;
	kvl.reserve(config.contentList.size());
	for (size_t i = 0; i < config.contentList.size(); ++i)
	  {
	    const KeyValue& kv = config.contentList[i];
	    kvl.push_back(new OptionList::KeyValue(kv.key, kv.value));
	  }
	const ParseClientConfig cc = ParseClientConfig::parse(config.content, &kvl, options);
#ifdef OPENVPN_DUMP_CONFIG
	std::cout << "---------- ARGS ----------" << std::endl;
	std::cout << options.render(Option::RENDER_PASS_FMT|Option::RENDER_NUMBER|Option::RENDER_BRACKET) << std::endl;
	std::cout << "---------- MAP ----------" << std::endl;
	std::cout << options.render_map() << std::endl;
#endif
	eval.error = cc.error();
	eval.message = cc.message();
	eval.userlockedUsername = cc.userlockedUsername();
	eval.profileName = cc.profileName();
	eval.friendlyName = cc.friendlyName();
	eval.autologin = cc.autologin();
	eval.externalPki = cc.externalPki();
	eval.staticChallenge = cc.staticChallenge();
	eval.staticChallengeEcho = cc.staticChallengeEcho();
	eval.privateKeyPasswordRequired = cc.privateKeyPasswordRequired();
	eval.allowPasswordSave = cc.allowPasswordSave();
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
	state->private_key_password = config.privateKeyPassword;
	if (!config.protoOverride.empty())
	  state->proto_override = Protocol::parse(config.protoOverride, false);
	if (!config.compressionMode.empty())
	  state->proto_context_options->parse_compression_mode(config.compressionMode);
	if (eval.externalPki)
	  state->external_pki_alias = config.externalPkiAlias;
	state->disable_client_cert = config.disableClientCert;
	state->default_key_direction = config.defaultKeyDirection;
	state->force_aes_cbc_ciphersuites = config.forceAesCbcCiphersuites;
	state->gui_version = config.guiVersion;
	if (!config.proxyHost.empty())
	  {
	    HTTPProxyTransport::Options::Ptr ho(new HTTPProxyTransport::Options());
	    ho->set_proxy_server(config.proxyHost, config.proxyPort);
	    ho->username = config.proxyUsername;
	    ho->password = config.proxyPassword;
	    ho->allow_cleartext_auth = config.proxyAllowCleartextAuth;
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
	cc->enable_password_cache(creds.cachePassword);
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
	cc.private_key_password = state->private_key_password;
	cc.disable_client_cert = state->disable_client_cert;
	cc.default_key_direction = state->default_key_direction;
	cc.force_aes_cbc_ciphersuites = state->force_aes_cbc_ciphersuites;
	cc.gui_version = state->gui_version;
#if defined(USE_TUN_BUILDER)
	cc.socket_protect = &state->socket_protect;
	cc.builder = this;
#endif

	// force Session ID use and disable password cache if static challenge is enabled
	if (state->creds
	    && !state->creds->get_replace_password_with_session_id()
	    && !state->eval.autologin
	    && !state->eval.staticChallenge.empty())
	  {
	    state->creds->set_replace_password_with_session_id(true);
	    state->creds->enable_password_cache(false);
	  }

	// external PKI
#if !defined(USE_APPLE_SSL)
	if (state->eval.externalPki && !state->disable_client_cert)
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

	  // if exception is an ExceptionCode, translate the code
	  // to return status string
	  {
	    const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
	    if (ec && ec->code_defined())
	      ret.status = Error::name(ec->code());
	  }
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

    OPENVPN_CLIENT_EXPORT bool OpenVPNClient::sign(const std::string& sig_type, const std::string& data, std::string& sig)
    {
      ExternalPKISignRequest req;
      req.sigType = sig_type;
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
      return (int)MySessionStats::combined_n();
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
		const unsigned int delta = (unsigned int)dur.to_binary_ms();
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

    OPENVPN_CLIENT_EXPORT void OpenVPNClient::pause(const std::string& reason)
    {
      ClientConnect::Ptr session = state->session;
      if (session)
	session->thread_safe_pause(reason);
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

    OPENVPN_CLIENT_EXPORT std::string OpenVPNClient::crypto_self_test()
    {
      return SelfTest::crypto_self_test();
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

    OPENVPN_CLIENT_EXPORT std::string OpenVPNClient::platform()
    {
      return platform_string();
    }

    OPENVPN_CLIENT_EXPORT OpenVPNClient::~OpenVPNClient()
    {
      delete state;
    }

    OPENVPN_CLIENT_EXPORT LogInfo::LogInfo(const std::string& str)
      : text(Unicode::utf8_printable(str, 4096 | Unicode::UTF8_PASS_FMT)) {}
  }
}
