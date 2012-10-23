//
//  cliopt.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_CLIENT_CLIOPT_H
#define OPENVPN_CLIENT_CLIOPT_H

#include <string>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/pki/epkibase.hpp>

#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/transport/reconnect_notify.hpp>
#include <openvpn/transport/client/udpcli.hpp>
#include <openvpn/transport/client/tcpcli.hpp>

#include <openvpn/client/cliproto.hpp>

#if defined(USE_TUN_BUILDER)
#include <openvpn/tun/builder/client.hpp>
#elif defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/mac/client/tuncli.hpp>
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
#if defined(USE_TUN_BUILDER)
	builder = NULL;
#endif
      }

      std::string server_override;
      Protocol proto_override;
      int conn_timeout;
      SessionStats::Ptr cli_stats;
      ClientEvent::Queue::Ptr cli_events;
      ProtoContextOptions::Ptr proto_context_options;
      bool tun_persist;

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
      : session_iteration(0),
	socket_protect(config.socket_protect),
	reconnect_notify(config.reconnect_notify),
	cli_stats(config.cli_stats),
	cli_events(config.cli_events),
	server_poll_timeout_(10),
	server_override(config.server_override),
	proto_override(config.proto_override),
	conn_timeout_(config.conn_timeout),
	proto_context_options(config.proto_context_options),
	tun_persist(config.tun_persist)
    {
      // initialize RNG/PRNG
      rng.reset(new RandomAPI());
      prng.reset(new PRNG<RandomAPI, ClientCryptoAPI>("SHA1", rng, 16));

      // frame
      frame = frame_init();

      // If running in tun_persist mode, we need to do basic DNS caching so that
      // we can avoid emitting DNS requests while the tunnel is blocked during
      // reconnections.
      if (tun_persist)
	endpoint_cache.reset(new EndpointCache());

      // client config
      ClientSSLAPI::Config cc;
      cc.set_external_pki_callback(config.external_pki);
      cc.frame = frame;
#ifdef OPENVPN_SSL_DEBUG
      cc.enable_debug();
#endif
#if defined(USE_POLARSSL) || defined(USE_POLARSSL_APPLE_HYBRID)
      cc.rng = rng;
#endif
      cc.load(opt);
      if (!cc.mode.is_client())
	throw option_error("only client configuration supported");

      // client ProtoContext config
      cp.reset(new Client::ProtoConfig());
      cp->load(opt, *proto_context_options);
      cp->ssl_ctx.reset(new ClientSSLAPI(cc));
      cp->frame = frame;
      cp->now = &now_;
      cp->rng = rng;
      cp->prng = prng;

      // load remote list
      remote_list.reset(new RemoteList(opt));
      if (!remote_list->size())
	throw option_error("no remote option specified");

      // initialize transport layer
      if (cp->layer != Layer(Layer::OSI_LAYER_3))
	throw option_error("only layer 3 currently supported");

      // init transport config
      const std::string session_name = load_transport_config();

      // initialize tun/tap
#if defined(USE_TUN_BUILDER)
      TunBuilderClient::ClientConfig::Ptr tunconf = TunBuilderClient::ClientConfig::new_obj();
      tunconf->builder = config.builder;
      tunconf->session_name = session_name;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#if defined(OPENVPN_PLATFORM_IPHONE)
      tunconf->retain_sd = true;
      tunconf->tun_prefix = true;
#else
      if (tun_persist)
	tunconf->tun_persist.reset(new TunBuilderClient::TunPersist);
#endif
#elif defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
      TunLinux::ClientConfig::Ptr tunconf = TunLinux::ClientConfig::new_obj();
      tunconf->layer = cp->layer;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#elif defined(OPENVPN_PLATFORM_MAC) && !defined(OPENVPN_FORCE_TUN_NULL)
      TunMac::ClientConfig::Ptr tunconf = TunMac::ClientConfig::new_obj();
      tunconf->layer = cp->layer;
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#else
      TunNull::ClientConfig::Ptr tunconf = TunNull::ClientConfig::new_obj();
      tunconf->frame = frame;
      tunconf->stats = cli_stats;
#endif
      tun_factory = tunconf;

      // server-poll-timeout
      {
	const Option *o = opt.get_ptr("server-poll-timeout");
	if (o)
	  server_poll_timeout_ = types<unsigned int>::parse(o->get(1));
      }

      // userlocked username
      {
	const Option* o = opt.get_ptr("USERNAME");
	if (o)
	  userlocked_username = o->get(1);
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
      }
    }

    void next()
    {
      ++session_iteration;
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
      cli_config->proto_context_config = cp;
      cli_config->proto_context_options = proto_context_options;
      cli_config->push_base = push_base;
      cli_config->transport_factory = transport_factory;
      cli_config->tun_factory = tun_factory;
      cli_config->cli_stats = cli_stats;
      cli_config->cli_events = cli_events;
      cli_config->creds = creds;
      return cli_config;
    }

    bool need_creds() const
    {
      return !cp->autologin;
    }

    void submit_creds(const ClientCreds::Ptr& creds_arg)
    {
      // if no username is defined in creds and userlocked_username is defined
      // in profile, set the creds username to be the userlocked_username
      if (creds_arg && !creds_arg->username_defined() && !userlocked_username.empty())
	creds_arg->set_username(userlocked_username);

      creds = creds_arg;
    }

    Time::Duration server_poll_timeout() const
    {
      return Time::Duration::seconds(server_poll_timeout_);
    }

    SessionStats& stats() { return *cli_stats; }
    ClientEvent::Queue& events() { return *cli_events; }

    int conn_timeout() const { return conn_timeout_; }

    void update_now()
    {
      now_.update();
    }

  private:
    std::string load_transport_config()
    {
      // During reconnects, if tun_persist is enabled and endpoint cache is enabled,
      // remote list scan should bypass any hosts not in endpoint cache.  This is done
      // because in tun_persist mode, DNS resolve requests are usually not viable
      // during reconnections because internet access (other than the tunnel itself)
      // is blocked.
      EndpointCache::Ptr ec;
      if (tun_persist && endpoint_cache && endpoint_cache->defined())
	ec = endpoint_cache;

      // initialize remote item with current element
      const RemoteList::Item rli = remote_list->get(session_iteration, server_override, proto_override, ec.get());
      cp->remote_adjust(rli);

      // initialize transport factory
      if (rli.transport_protocol.is_udp())
	{
	  UDPTransport::ClientConfig::Ptr udpconf = UDPTransport::ClientConfig::new_obj();
	  udpconf->server_host = rli.server_host;
	  udpconf->server_port = rli.server_port;
	  udpconf->frame = frame;
	  udpconf->stats = cli_stats;
	  udpconf->socket_protect = socket_protect;
	  udpconf->endpoint_cache = endpoint_cache;
	  transport_factory = udpconf;
	}
      else if (rli.transport_protocol.is_tcp())
	{
	  TCPTransport::ClientConfig::Ptr tcpconf = TCPTransport::ClientConfig::new_obj();
	  tcpconf->server_host = rli.server_host;
	  tcpconf->server_port = rli.server_port;
	  tcpconf->frame = frame;
	  tcpconf->stats = cli_stats;
	  tcpconf->socket_protect = socket_protect;
	  tcpconf->endpoint_cache = endpoint_cache;
	  transport_factory = tcpconf;
	}
      else
	throw option_error("unknown transport protocol");

      return rli.server_host;
    }

    unsigned int session_iteration;

    Time now_; // current time
    RandomAPI::Ptr rng;
    PRNG<RandomAPI, ClientCryptoAPI>::Ptr prng;
    Frame::Ptr frame;
    ClientSSLAPI::Config cc;
    Client::ProtoConfig::Ptr cp;
    RemoteList::Ptr remote_list;
    TransportClientFactory::Ptr transport_factory;
    TunClientFactory::Ptr tun_factory;
    EndpointCache::Ptr endpoint_cache;
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
    std::string userlocked_username;
    PushOptionsBase::Ptr push_base;
    bool tun_persist;
  };
}

#endif
