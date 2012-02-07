#ifndef OPENVPN_CLIENT_CLIOPT_H
#define OPENVPN_CLIENT_CLIOPT_H

#include <string>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/init/initprocess.hpp>
#include <openvpn/frame/frame_init.hpp>

#include <openvpn/transport/client/udpcli.hpp>
#include <openvpn/transport/client/tcpcli.hpp>

#include <openvpn/client/cliproto.hpp>

#if defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/linux/client/tuncli.hpp>
#elif defined(OPENVPN_PLATFORM_MAC) && !defined(OPENVPN_FORCE_TUN_NULL)
#include <openvpn/tun/mac/client/tuncli.hpp>
#else
#include <openvpn/tun/client/tunnull.hpp>
#endif

#ifdef USE_APPLE_SSL
#include <openvpn/applecrypto/ssl/sslctx.hpp>
#endif

#ifdef USE_OPENSSL
#include <openvpn/openssl/ssl/sslctx.hpp>
#endif

using namespace openvpn;

namespace openvpn {

  class ClientOptions : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientOptions> Ptr;

#if defined(USE_OPENSSL)
    typedef OpenSSLContext ClientSSLContext;
#elif defined(USE_APPLE_SSL)
    typedef AppleSSLContext ClientSSLContext;
#else
#error no SSL library defined
#endif
    typedef ClientProto::Session<ClientSSLContext> Client;

    ClientOptions(const OptionList& opt,
		  const SessionStats::Ptr& cli_stats_arg,
		  const ClientEvent::Queue::Ptr& cli_events_arg)
      : session_iteration(0),
	cli_stats(cli_stats_arg),
	cli_events(cli_events_arg),
	server_poll_timeout_(10)
    {
      // initialize PRNG
      prng.reset(new PRNG("SHA1", 16));

      // frame
      frame = frame_init();

      // client config
      ClientSSLContext::Config cc;
      cc.load(opt);
      cc.frame = frame;
#ifdef OPENVPN_SSL_DEBUG
      cc.enable_debug();
#endif
      if (!cc.mode.is_client())
	throw option_error("only client configuration supported");

      // client ProtoContext config
      cp.reset(new Client::ProtoConfig);
      cp->load(opt);
      cp->ssl_ctx.reset(new ClientSSLContext(cc));
      cp->frame = frame;
      cp->now = &now_;
      cp->prng = prng;

      // load remote list
      remote_list.reset(new RemoteList(opt));
      if (!remote_list->size())
	throw option_error("no remote option specified");

      // initialize transport layer
      if (cp->layer != Layer(Layer::OSI_LAYER_3))
	throw option_error("only layer 3 currently supported");

      // init transport config
      load_transport_config();

      // initialize tun/tap
#if defined(OPENVPN_PLATFORM_LINUX) && !defined(OPENVPN_FORCE_TUN_NULL)
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
    }

    void next()
    {
      ++session_iteration;
      load_transport_config();
    }

    Client::Config::Ptr client_config()
    {
      Client::Config::Ptr cli_config = new Client::Config;
      cli_config->proto_context_config = cp;
      cli_config->transport_factory = transport_factory;
      cli_config->tun_factory = tun_factory;
      cli_config->cli_stats = cli_stats;
      cli_config->cli_events = cli_events;
      cli_config->username = username_;
      cli_config->password = password_;
      return cli_config;
    }

    bool need_creds() const
    {
      return !cp->autologin;
    }

    void submit_creds(const std::string& username, const std::string& password)
    {
      username_ = username;
      password_ = password;
    }

    Time::Duration server_poll_timeout() const
    {
      return Time::Duration::seconds(server_poll_timeout_);
    }

    SessionStats& stats() { return *cli_stats; }
    ClientEvent::Queue& events() { return *cli_events; }

  private:
    void load_transport_config()
    {
      // initialize remote item with first element
      const RemoteList::Item& rli = remote_list->modulo_ref(session_iteration);
      cp->remote_adjust(rli);

      // initialize transport factory
      if (rli.transport_protocol.is_udp())
	{
	  UDPTransport::ClientConfig::Ptr udpconf = UDPTransport::ClientConfig::new_obj();
	  udpconf->server_host = rli.server_host;
	  udpconf->server_port = rli.server_port;
	  udpconf->frame = frame;
	  udpconf->stats = cli_stats;
	  transport_factory = udpconf;
	}
      else if (rli.transport_protocol.is_tcp())
	{
	  TCPTransport::ClientConfig::Ptr tcpconf = TCPTransport::ClientConfig::new_obj();
	  tcpconf->server_host = rli.server_host;
	  tcpconf->server_port = rli.server_port;
	  tcpconf->frame = frame;
	  tcpconf->stats = cli_stats;
	  transport_factory = tcpconf;
	}
      else
	throw option_error("unknown transport protocol");
    }

    unsigned int session_iteration;

    Time now_; // current time
    PRNG::Ptr prng;
    Frame::Ptr frame;
    ClientSSLContext::Config cc;
    Client::ProtoConfig::Ptr cp;
    RemoteList::Ptr remote_list;
    TransportClientFactory::Ptr transport_factory;
    TunClientFactory::Ptr tun_factory;
    SessionStats::Ptr cli_stats;
    ClientEvent::Queue::Ptr cli_events;
    std::string username_;
    std::string password_;
    unsigned int server_poll_timeout_;
  };
}

#endif
