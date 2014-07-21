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

// These classes encapsulate the basic setup of the various objects needed to
// create an OpenVPN client session.  The basic idea here is to look at both
// compile time settings (i.e. crypto/SSL/random libraries), and run-time
// (such as transport layer using UDP, TCP, or HTTP-proxy), and
// build the actual objects that will be used to construct a client session.

#ifndef OPENVPN_CLIENT_CLIOPT_H
#define OPENVPN_CLIENT_CLIOPT_H

#include <string>

#include <openvpn/error/excode.hpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/pki/epkibase.hpp>

#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/transport/reconnect_notify.hpp>
#include <openvpn/transport/client/udpcli.hpp>
#include <openvpn/transport/client/tcpcli.hpp>
#include <openvpn/transport/client/httpcli.hpp>

#include <openvpn/client/cliproto.hpp>
#include <openvpn/client/cliopthelper.hpp>
#include <openvpn/client/optfilt.hpp>
#include <openvpn/client/clilife.hpp>

#if defined(USE_TUN_BUILDER)
#include <openvpn/tun/builder/client.hpp>
#elif defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/mac/client/tuncli.hpp>
#include <openvpn/apple/maclife.hpp>
#elif defined(OPENVPN_PLATFORM_WIN) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/win/client/tuncli.hpp>
#else
#include <openvpn/tun/client/tunnull.hpp>
#endif

#ifdef USE_OPENSSL
#include <openvpn/openssl/crypto/api.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/openssl/util/rand.hpp>
#endif

#ifdef USE_APPLE_SSL
#include <openvpn/applecrypto/crypto/api.hpp>
#include <openvpn/applecrypto/ssl/sslctx.hpp>
#include <openvpn/applecrypto/util/rand.hpp>
#endif

#ifdef USE_POLARSSL
#include <openvpn/polarssl/crypto/api.hpp>
#include <openvpn/polarssl/ssl/sslctx.hpp>
#include <openvpn/polarssl/util/rand.hpp>
#endif

#ifdef USE_POLARSSL_APPLE_HYBRID
#include <openvpn/applecrypto/crypto/api.hpp>
#include <openvpn/polarssl/ssl/sslctx.hpp>
#include <openvpn/applecrypto/util/rand.hpp>
#endif

namespace openvpn {

  class ClientOptions : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientOptions> Ptr;

#if defined(USE_POLARSSL)
    typedef PolarSSLCryptoAPI ClientCryptoAPI;
    typedef PolarSSLContext<PolarSSLRandom> ClientSSLAPI;
    typedef PolarSSLRandom RandomAPI;
#elif defined(USE_POLARSSL_APPLE_HYBRID)
    // Uses Apple framework for RandomAPI and ClientCryptoAPI and PolarSSL for ClientSSLAPI
    typedef AppleCryptoAPI ClientCryptoAPI;
    typedef PolarSSLContext<AppleRandom> ClientSSLAPI;
    typedef AppleRandom RandomAPI;
#elif defined(USE_APPLE_SSL)
    typedef AppleCryptoAPI ClientCryptoAPI;
    typedef AppleSSLContext ClientSSLAPI;
    typedef AppleRandom RandomAPI;
#elif defined(USE_OPENSSL)
    typedef OpenSSLCryptoAPI ClientCryptoAPI;
    typedef OpenSSLContext ClientSSLAPI;
    typedef OpenSSLRandom RandomAPI;
#else
#error no SSL library defined
#endif
    typedef ClientProto::Session<RandomAPI, ClientCryptoAPI, ClientSSLAPI> Client;

    struct Config {
      Config()
      {
	external_pki = NULL;
	socket_protect = NULL;
	reconnect_notify = NULL;
	conn_timeout = 0;
	tun_persist = false;
	google_dns_fallback = false;
	disable_client_cert = false;
	default_key_direction = -1;
	force_aes_cbc_ciphersuites = false;
#if defined(USE_TUN_BUILDER)
	builder = NULL;
#endif
      }

      std::string gui_version;
      std::string server_override;
      Protocol proto_override;
      int conn_timeout;
      SessionStats::Ptr cli_stats;
      ClientEvent::Queue::Ptr cli_events;
      ProtoContextOptions::Ptr proto_context_options;
      HTTPProxyTransport::Options::Ptr http_proxy_options;
      bool tun_persist;
      bool google_dns_fallback;
      std::string private_key_password;
      bool disable_client_cert;
      int default_key_direction;
      bool force_aes_cbc_ciphersuites;

      // callbacks -- must remain in scope for lifetime of ClientOptions object
      ExternalPKIBase* external_pki;
      SocketProtect* socket_protect;
      ReconnectNotify* reconnect_notify;
#if defined(USE_TUN_BUILDER)
      TunBuilderBase* builder;
#endif
    };

    ClientOptions(const OptionList& opt,   // only needs to remain in scope for duration of constructor call
		  const Config& config)
      : socket_protect(config.socket_protect),
	reconnect_notify(config.reconnect_notify),
	cli_stats(config.cli_stats),
	cli_events(config.cli_events),
	server_poll_timeout_(10),
	server_override(config.server_override),
	proto_override(config.proto_override),
	conn_timeout_(config.conn_timeout),
	proto_context_options(config.proto_context_options),
	http_proxy_options(config.http_proxy_options),
	autologin(false),
	creds_locked(false)
    {
      // parse general client options
      const ParseClientConfig pcc(opt);

      // creds
      userlocked_username = pcc.userlockedUsername();
      autologin = pcc.autologin();

      // initialize RNG/PRNG
      rng.reset(new RandomAPI());
      prng.reset(new PRNG<RandomAPI, ClientCryptoAPI>("SHA1", rng, 16)); // fixme: hangs on OS X 10.6 with USE_POLARSSL_APPLE_HYBRID

      // frame
      frame = frame_init();

      // route-nopull
      pushed_options_filter.reset(new PushedOptionsFilter(opt.exists("route-nopull")));

      // client SSL config
      ClientSSLAPI::Config cc;
      cc.set_external_pki_callback(config.external_pki);
      cc.frame = frame;
#ifdef OPENVPN_SSL_DEBUG
      cc.ssl_debug_level = OPENVPN_SSL_DEBUG;
#endif
#if defined(USE_POLARSSL) || defined(USE_POLARSSL_APPLE_HYBRID)
      cc.rng = rng;
#endif
#if defined(USE_POLARSSL) || defined(USE_POLARSSL_APPLE_HYBRID) || defined(USE_OPENSSL)
      cc.local_cert_enabled = (pcc.clientCertEnabled() && !config.disable_client_cert);
      cc.set_private_key_password(config.private_key_password);
      cc.force_aes_cbc_ciphersuites = config.force_aes_cbc_ciphersuites;
#endif
      cc.load(opt);
      if (!cc.mode.is_client())
	throw option_error("only client configuration supported");

      // client ProtoContext config
      cp.reset(new Client::ProtoConfig());
      cp->load(opt, *proto_context_options, config.default_key_direction);
      cp->set_xmit_creds(!autologin || pcc.hasEmbeddedPassword());
      cp->ssl_ctx.reset(new ClientSSLAPI(cc));
      cp->gui_version = config.gui_version;
      cp->frame = frame;
      cp->now = &now_;
      cp->rng = rng;
      cp->prng = prng;

      // If HTTP proxy parameters are not supplied by API, try to get them from config
      if (!http_proxy_options)
	http_proxy_options = HTTPProxyTransport::Options::parse(opt);

      // load remote list
      remote_list.reset(new RemoteList(opt, true));
      if (!remote_list->defined())
	throw option_error("no remote option specified");

      // If running in tun_persist mode, we need to do basic DNS caching so that
      // we can avoid emitting DNS requests while the tunnel is blocked during
      // reconnections.
      remote_list->set_enable_cache(config.tun_persist);

      // process server override
      remote_list->set_server_override(config.server_override);

      // process protocol override, should be called after set_enable_cache
      remote_list->handle_proto_override(config.proto_override, bool(http_proxy_options));

      // process remote-random
      if (opt.exists("remote-random"))
	remote_list->randomize(*prng);

      // special remote cache handling for HTTP proxy
      if (http_proxy_options)
	{
	  remote_list->set_enable_cache(false); // remote server addresses will be resolved by proxy
	  http_proxy_options->proxy_server_set_enable_cache(config.tun_persist);
	}

      // secret option not supported
      if (opt.exists("secret"))
	throw option_error("sorry, static key encryption mode (non-SSL/TLS) is not supported");

      // fragment option not supported
      if (opt.exists("fragment"))
	throw option_error("sorry, 'fragment' directive is not supported, nor is connecting to a server that uses 'fragment' directive");

      // init transport config
      const std::string session_name = load_transport_config();

      // get tun-mtu parameter from config
      unsigned int tun_mtu = 0;
      {
	const Option *o = opt.get_ptr("tun-mtu");
	if (o)
	  tun_mtu = parse_number_throw<unsigned int>(o->get(1, 16), "tun-mtu");
      }

      // initialize tun/tap
#if defined(USE_TUN_BUILDER)
      TunBuilderClient::ClientConfig::Ptr tunconf = TunBuilderClient::ClientConfig::new_obj();
      tunconf->builder = config.builder;
      tunconf->tun_prop.session_name = session_name;
      tunconf->tun_prop.google_dns_fallback = config.google_dns_fallback;
      if (tun_mtu)
	tunconf->tun_prop.mtu = tun_mtu;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#if defined(OPENVPN_PLATFORM_IPHONE)
      tunconf->retain_sd = true;
      tunconf->tun_prefix = true;
#endif
      if (config.tun_persist)
	tunconf->tun_persist.reset(new TunBuilderClient::TunPersist(true, tunconf->retain_sd, config.builder));
#elif defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
      TunLinux::ClientConfig::Ptr tunconf = TunLinux::ClientConfig::new_obj();
      tunconf->layer = cp->layer;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
      if (tun_mtu)
	tunconf->mtu = tun_mtu;
#elif defined(OPENVPN_PLATFORM_MAC) && !defined(OPENVPN_FORCE_TUN_NULL)
      TunMac::ClientConfig::Ptr tunconf = TunMac::ClientConfig::new_obj();
      tunconf->layer = cp->layer;
      tunconf->tun_prop.session_name = session_name;
      tunconf->tun_prop.google_dns_fallback = config.google_dns_fallback;
      if (tun_mtu)
	tunconf->tun_prop.mtu = tun_mtu;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
      tunconf->enable_failsafe_block = config.tun_persist;
      client_lifecycle.reset(new MacLifeCycle);
#elif defined(OPENVPN_PLATFORM_WIN) && !defined(OPENVPN_FORCE_TUN_NULL)
      TunWin::ClientConfig::Ptr tunconf = TunWin::ClientConfig::new_obj();
      tunconf->tun_prop.session_name = session_name;
      tunconf->tun_prop.google_dns_fallback = config.google_dns_fallback;
      if (tun_mtu)
	tunconf->tun_prop.mtu = tun_mtu;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
      if (config.tun_persist)
	tunconf->tun_persist.reset(new TunWin::TunPersist(true, false, NULL));
#else
      TunNull::ClientConfig::Ptr tunconf = TunNull::ClientConfig::new_obj();
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#endif

      // verify that tun implementation can handle OSI layer declared by config
      if (cp->layer == Layer(Layer::OSI_LAYER_2) && !tunconf->layer_2_supported())
	throw ErrorCode(Error::TAP_NOT_SUPPORTED, true, "OSI layer 2 tunnels are not currently supported");

      // save tun factory
      tun_factory = tunconf;

      // server-poll-timeout
      {
	const Option *o = opt.get_ptr("server-poll-timeout");
	if (o)
	  server_poll_timeout_ = parse_number_throw<unsigned int>(o->get(1, 16), "server-poll-timeout");
      }

      // create default creds object in case submit_creds is not called,
      // and populate it with embedded creds, if available
      {
	ClientCreds::Ptr cc = new ClientCreds();
	if (pcc.hasEmbeddedPassword())
	  {
	    cc->set_username(userlocked_username);
	    cc->set_password(pcc.embeddedPassword());
	    submit_creds(cc);
	    creds_locked = true;
	  }
	else
	  submit_creds(cc);
      }

      // configure push_base, a set of base options that will be combined with
      // options pushed by server.
      {
	push_base.reset(new PushOptionsBase());

	// base options where multiple options of the same type can aggregate
	push_base->multi.extend(opt, "route");
	push_base->multi.extend(opt, "route-ipv6");
	push_base->multi.extend(opt, "redirect-gateway");
	push_base->multi.extend(opt, "redirect-private");
	push_base->multi.extend(opt, "dhcp-option");

	// base options where only a single instance of each option makes sense
	push_base->singleton.extend(opt, "redirect-dns");
	push_base->singleton.extend(opt, "inactive");
      }

      // show unused options
      if (opt.n_unused())
	OPENVPN_LOG("UNUSED OPTIONS" << std::endl << opt.render(Option::RENDER_TRUNC_64|Option::RENDER_NUMBER|Option::RENDER_BRACKET|Option::RENDER_UNUSED));
    }

    void next()
    {
      remote_list->next();
      load_transport_config();
    }

    bool pause_on_connection_timeout()
    {
      if (reconnect_notify)
	return reconnect_notify->pause_on_connection_timeout();
      else
	return false;
    }

    Client::Config::Ptr client_config()
    {
      Client::Config::Ptr cli_config = new Client::Config;

      // Copy ProtoConfig so that modifications due to server push will
      // not persist across client instantiations.
      cli_config->proto_context_config.reset(new Client::ProtoConfig(*cp));

      cli_config->proto_context_options = proto_context_options;
      cli_config->push_base = push_base;
      cli_config->transport_factory = transport_factory;
      cli_config->tun_factory = tun_factory;
      cli_config->cli_stats = cli_stats;
      cli_config->cli_events = cli_events;
      cli_config->creds = creds;
      cli_config->pushed_options_filter = pushed_options_filter;
      return cli_config;
    }

    bool need_creds() const
    {
      return !autologin;
    }

    void submit_creds(const ClientCreds::Ptr& creds_arg)
    {
      if (creds_arg && !creds_locked)
	{
	  // if no username is defined in creds and userlocked_username is defined
	  // in profile, set the creds username to be the userlocked_username
	  if (!creds_arg->username_defined() && !userlocked_username.empty())
	    creds_arg->set_username(userlocked_username);
	  creds = creds_arg;
	}
    }

    bool server_poll_timeout_enabled() const
    {
      return !http_proxy_options;
    }

    Time::Duration server_poll_timeout() const
    {
      return Time::Duration::seconds(server_poll_timeout_);
    }

    SessionStats& stats() { return *cli_stats; }
    const SessionStats::Ptr& stats_ptr() const { return cli_stats; }
    ClientEvent::Queue& events() { return *cli_events; }
    const RemoteList::Ptr& remote_list_ptr() const { return remote_list; }
    ClientLifeCycle* lifecycle() { return client_lifecycle.get(); }

    int conn_timeout() const { return conn_timeout_; }

    void update_now()
    {
      now_.update();
    }

    void finalize(const bool disconnected)
    {
      if (tun_factory)
	tun_factory->finalize(disconnected);
    }

  private:
    std::string load_transport_config()
    {
      // get current transport protocol
      const Protocol& transport_protocol = remote_list->current_transport_protocol();

      // set transport protocol in Client::ProtoConfig
      cp->set_protocol(transport_protocol);

      // construct transport object
      if (http_proxy_options)
	{
	  // HTTP proxy always uses TCP.  If current transport protocol is not TCP, this is
	  // an error that should have been caught earlier in RemoteList::handle_proto_override.
	  if (!transport_protocol.is_tcp())
	    throw option_error("internal error: no TCP server entries for HTTP proxy transport");

	  // HTTP Proxy transport
	  HTTPProxyTransport::ClientConfig<RandomAPI, ClientCryptoAPI>::Ptr httpconf = HTTPProxyTransport::ClientConfig<RandomAPI, ClientCryptoAPI>::new_obj();
	  httpconf->remote_list = remote_list;
	  httpconf->frame = frame;
	  httpconf->stats = cli_stats;
	  httpconf->socket_protect = socket_protect;
	  httpconf->http_proxy_options = http_proxy_options;
	  httpconf->rng = rng;
	  transport_factory = httpconf;
	}
      else
	{
	  if (transport_protocol.is_udp())
	    {
	      // UDP transport
	      UDPTransport::ClientConfig::Ptr udpconf = UDPTransport::ClientConfig::new_obj();
	      udpconf->remote_list = remote_list;
	      udpconf->frame = frame;
	      udpconf->stats = cli_stats;
	      udpconf->socket_protect = socket_protect;
	      transport_factory = udpconf;
	    }
	  else if (transport_protocol.is_tcp())
	    {
	      // TCP transport
	      TCPTransport::ClientConfig::Ptr tcpconf = TCPTransport::ClientConfig::new_obj();
	      tcpconf->remote_list = remote_list;
	      tcpconf->frame = frame;
	      tcpconf->stats = cli_stats;
	      tcpconf->socket_protect = socket_protect;
	      transport_factory = tcpconf;
	    }
	  else
	    throw option_error("internal error: unknown transport protocol");
	}
      return remote_list->current_server_host();
    }

    Time now_; // current time
    RandomAPI::Ptr rng;
    PRNG<RandomAPI, ClientCryptoAPI>::Ptr prng;
    Frame::Ptr frame;
    ClientSSLAPI::Config cc;
    Client::ProtoConfig::Ptr cp;
    RemoteList::Ptr remote_list;
    TransportClientFactory::Ptr transport_factory;
    TunClientFactory::Ptr tun_factory;
    SocketProtect* socket_protect;
    ReconnectNotify* reconnect_notify;
    SessionStats::Ptr cli_stats;
    ClientEvent::Queue::Ptr cli_events;
    ClientCreds::Ptr creds;
    unsigned int server_poll_timeout_;
    std::string server_override;
    Protocol proto_override;
    int conn_timeout_;
    ProtoContextOptions::Ptr proto_context_options;
    HTTPProxyTransport::Options::Ptr http_proxy_options;
    std::string userlocked_username;
    bool autologin;
    bool creds_locked;
    PushOptionsBase::Ptr push_base;
    OptionList::FilterBase::Ptr pushed_options_filter;
    ClientLifeCycle::Ptr client_lifecycle;
  };
}

#endif
