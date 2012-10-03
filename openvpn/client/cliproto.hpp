//
//  cliproto.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_CLIENT_CLIPROTO_H
#define OPENVPN_CLIENT_CLIPROTO_H

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/cstdint.hpp> // for boost::uint...
#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with and trim_left_copy

#include <openvpn/common/rc.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/options/continuation.hpp>
#include <openvpn/options/sanitize.hpp>
#include <openvpn/client/clievent.hpp>
#include <openvpn/client/clicreds.hpp>
#include <openvpn/options/clihalt.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/coarsetime.hpp>

#include <openvpn/ssl/proto.hpp>

#ifdef OPENVPN_DEBUG_CLIPROTO
#define OPENVPN_LOG_CLIPROTO(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_CLIPROTO(x)
#endif

namespace openvpn {
  namespace ClientProto {

    struct NotifyCallback {
      virtual void client_proto_terminate() = 0;
      virtual void client_proto_connected() {}
    };

    template <typename RAND_API, typename CRYPTO_API, typename SSL_API>
    class Session : public ProtoContext<RAND_API, CRYPTO_API, SSL_API>, TransportClientParent, TunClientParent
    {
      typedef ProtoContext<RAND_API, CRYPTO_API, SSL_API> Base;
      typedef typename Base::PacketType PacketType;

      using Base::now;
      using Base::stat;

    public:
      typedef boost::intrusive_ptr<Session> Ptr;
      typedef typename Base::Config ProtoConfig;

      OPENVPN_EXCEPTION(client_exception);
      OPENVPN_EXCEPTION(client_halt_restart);
      OPENVPN_EXCEPTION(tun_exception);
      OPENVPN_EXCEPTION(transport_exception);
      OPENVPN_EXCEPTION(max_pushed_options_exceeded);
      OPENVPN_SIMPLE_EXCEPTION(session_invalidated);
      OPENVPN_SIMPLE_EXCEPTION(authentication_failed);

      struct Config : public RC<thread_unsafe_refcount>
      {
	typedef boost::intrusive_ptr<Config> Ptr;

	Config()
	  : max_pushed_options(256)
	{}

	typename ProtoConfig::Ptr proto_context_config;
	ProtoContextOptions::Ptr proto_context_options;
	PushOptionsBase::Ptr push_base;
	TransportClientFactory::Ptr transport_factory;
	TunClientFactory::Ptr tun_factory;
	SessionStats::Ptr cli_stats;
	ClientEvent::Queue::Ptr cli_events;
	ClientCreds::Ptr creds;
	unsigned int max_pushed_options;
      };

      Session(boost::asio::io_service& io_service_arg,
	      const Config& config,
	      NotifyCallback* notify_callback_arg)
	: Base(config.proto_context_config, config.cli_stats),
	  io_service(io_service_arg),
	  transport_factory(config.transport_factory),
	  tun_factory(config.tun_factory),
	  notify_callback(notify_callback_arg),
	  housekeeping_timer(io_service_arg),
	  push_request_timer(io_service_arg),
	  halt(false),
	  received_options(config.push_base),
	  creds(config.creds),
	  proto_context_options(config.proto_context_options),
	  first_packet_received_(false),
	  sent_push_request(false),
	  cli_events(config.cli_events),
	  connected_(false),
	  fatal_(Error::SUCCESS),
	  max_pushed_options(config.max_pushed_options)
      {
#ifdef OPENVPN_PACKET_LOG
	packet_log.open(OPENVPN_PACKET_LOG, std::ios::binary);
	if (!packet_log)
	  OPENVPN_THROW(open_file_error, "cannot open packet log for output: " << OPENVPN_PACKET_LOG);
#endif
	Base::update_now();
	Base::reset();
	//Base::enable_strict_openvpn_2x();
      }

      bool first_packet_received() const { return first_packet_received_; }

      void start()
      {
	if (!halt)
	  {
	    Base::update_now();

	    // coarse wakeup range
	    housekeeping_schedule.init(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024));

	    // initialize transport-layer packet handler
	    transport = transport_factory->new_client_obj(io_service, *this);
	    transport->start();
	  }
      }

      void send_explicit_exit_notify()
      {
	if (!halt)
	  Base::send_explicit_exit_notify();
      }

      void stop(const bool call_terminate_callback)
      {
	if (!halt)
	  {
	    halt = true;
	    housekeeping_timer.cancel();
	    push_request_timer.cancel();
	    if (tun)
	      tun->stop();
	    if (transport)
	      transport->stop();
	    if (notify_callback && call_terminate_callback)
	      notify_callback->client_proto_terminate();
	  }
      }

      void stop_on_signal(const boost::system::error_code& error, int signal_number)
      {
	stop(true);
      }

      bool reached_connected_state() const { return connected_; }

      // Fatal error means that we shouldn't retry.
      // Returns a value != Error::SUCCESS if error
      Error::Type fatal() const { return fatal_; }
      const std::string& fatal_reason() const { return fatal_reason_; }

      virtual ~Session()
      {
	stop(false);
      }

    private:
      // transport obj calls here with incoming packets
      virtual void transport_recv(BufferAllocated& buf)
      {
	try {
	  OPENVPN_LOG_CLIPROTO("Transport RECV " << server_endpoint_render() << ' ' << Base::dump_packet(buf));

	  // update current time
	  Base::update_now();

	  // update last packet received
	  stat().update_last_packet_received(now());

	  // log connecting event (only on first packet received)
	  if (!first_packet_received_)
	    {
	      ClientEvent::Base::Ptr ev = new ClientEvent::Connecting();
	      cli_events->add_event(ev);
	      first_packet_received_ = true;
	    }

	  // get packet type
	  typename Base::PacketType pt = Base::packet_type(buf);

	  // process packet
	  if (tun && pt.is_data())
	    {
	      // data packet
	      Base::data_decrypt(pt, buf);
	      if (buf.size())
		{
#ifdef OPENVPN_PACKET_LOG
		  log_packet(buf, false);
#endif
		  // make packet appear as incoming on tun interface
		  OPENVPN_LOG_CLIPROTO("TUN send, size=" << buf.size());
		  tun->tun_send(buf);
		}

	      // do a lightweight flush
	      Base::flush(false);
	    }
	  else if (pt.is_control())
	    {
	      // control packet
	      Base::control_net_recv(pt, buf);

	      // do a full flush
	      Base::flush(true);
	    }

	  // schedule housekeeping wakeup
	  set_housekeeping_timer();
	}
	catch (const std::exception& e)
	  {
	    process_exception(e, "transport_recv");
	  }
      }

      // tun i/o driver calls here with incoming packets
      virtual void tun_recv(BufferAllocated& buf)
      {
	try {
	  OPENVPN_LOG_CLIPROTO("TUN recv, size=" << buf.size());

	  // update current time
	  Base::update_now();

	  // encrypt packet
#ifdef OPENVPN_PACKET_LOG
	  log_packet(buf, true);
#endif
	  Base::data_encrypt(buf);
	  if (buf.size())
	    {
	      // send packet via transport to destination
	      OPENVPN_LOG_CLIPROTO("Transport SEND " << server_endpoint_render() << ' ' << Base::dump_packet(buf));
	      if (transport->transport_send(buf))
		Base::update_last_sent();
	    }

	  // do a lightweight flush
	  Base::flush(false);

	  // schedule housekeeping wakeup
	  set_housekeeping_timer();
	}
	catch (const std::exception& e)
	  {
	    process_exception(e, "tun_recv");
	  }
      }

      virtual void transport_pre_resolve()
      {
	ClientEvent::Base::Ptr ev = new ClientEvent::Resolve();
	cli_events->add_event(ev);
      }

      std::string server_endpoint_render()
      {
	std::string server_host, server_port, server_proto, server_ip;
	transport->server_endpoint_info(server_host, server_port, server_proto, server_ip);
	std::ostringstream out;
	out << server_host << ":" << server_port << " (" << server_ip << ") via " << server_proto;
	return out.str();
      }

      virtual void transport_connecting()
      {
	try {
	  OPENVPN_LOG("Connecting to " << server_endpoint_render());
	  ClientEvent::Base::Ptr ev = new ClientEvent::Wait();
	  cli_events->add_event(ev);
	  Base::start();
	  Base::flush(true);
	  set_housekeeping_timer();
	}
	catch (const std::exception& e)
	  {
	    process_exception(e, "transport_connecting");
	  }
      }

      virtual void transport_error(const std::exception& err)
      {
	if (notify_callback)
	  {
	    OPENVPN_LOG("Transport Error: " << err.what());
	    stop(true);
	  }
	else
	  throw transport_exception(err.what());
      }

      void extract_auth_token(const OptionList& opt)
      {
	// if auth-token is present, use it as the password for future renegotiations
	const Option* o = opt.get_ptr("auth-token");
	if (o)
	  {
	    o->min_args(2);
	    const std::string& sess_id = (*o)[1];
	    if (creds)
	      creds->set_session_id(sess_id);
#ifdef OPENVPN_SHOW_SESSION_TOKEN
	    OPENVPN_LOG("using session token " << sess_id);
#else
	    OPENVPN_LOG("using session token");
#endif
	  }
      }

      // proto base class calls here for control channel network sends
      virtual void control_net_send(const Buffer& net_buf)
      {
	OPENVPN_LOG_CLIPROTO("Transport SEND " << server_endpoint_render() << ' ' << Base::dump_packet(net_buf));
	if (transport->transport_send_const(net_buf))
	  Base::update_last_sent();
      }

      // proto base class calls here for app-level control-channel messages received
      virtual void control_recv(BufferPtr& app_bp)
      {
	const std::string msg = Base::template read_control_string<std::string>(*app_bp);
	//OPENVPN_LOG("SERVER: " << sanitize_control_message(msg));
	if (!received_options.complete() && boost::algorithm::starts_with(msg, "PUSH_REPLY,"))
	  {
	    // parse the received options
	    received_options.add(OptionList::parse_from_csv_static(msg.substr(11)));
	    if (received_options.size() > max_pushed_options)
	      OPENVPN_THROW(max_pushed_options_exceeded, "max number of allowed pushed options is " << max_pushed_options);
	    if (received_options.complete())
	      {
		// show options
		OPENVPN_LOG("OPTIONS:" << std::endl << render_options_sanitized(received_options));

		// process auth-token
		extract_auth_token(received_options);

		// modify proto config (cipher, auth, and compression methods)
		Base::process_push(received_options, *proto_context_options);

		// initialize tun/routing
		tun = tun_factory->new_client_obj(io_service, *this);
		tun->client_start(received_options, *transport);
	      }
	    else
	      OPENVPN_LOG("Options continuation...");
	  }
	else if (boost::algorithm::starts_with(msg, "AUTH_FAILED"))
	  {
	    fatal_ = Error::AUTH_FAILED;
	    if (msg.length() >= 13)
	      fatal_reason_ = boost::algorithm::trim_left_copy(std::string(msg, 12));
	    if (notify_callback)
	      {
		OPENVPN_LOG("AUTH_FAILED");
		stop(true);
	      }
	    else
	      throw authentication_failed();
	  }
	else if (ClientHalt::match(msg))
	  {
	    const ClientHalt ch(msg);
	    process_halt_restart(ch);
	  }
      }

      virtual void tun_pre_tun_config()
      {
	ClientEvent::Base::Ptr ev = new ClientEvent::AssignIP();
	cli_events->add_event(ev);
      }

      virtual void tun_pre_route_config()
      {
	ClientEvent::Base::Ptr ev = new ClientEvent::AddRoutes();
	cli_events->add_event(ev);
      }

      virtual void tun_connected()
      {
	OPENVPN_LOG("Connected via " + tun->tun_name());

	ClientEvent::Connected::Ptr ev = new ClientEvent::Connected();
	if (creds)
	  ev->user = creds->get_username();
	transport->server_endpoint_info(ev->server_host, ev->server_port, ev->server_proto, ev->server_ip);
	ev->vpn_ip4 = tun->vpn_ip4();
	ev->vpn_ip6 = tun->vpn_ip6();
	try {
	  std::string client_ip = received_options.get_optional("client-ip", 1);
	  if (client_ip.length() <= 64)
	    ev->client_ip = client_ip;
	}
	catch (const std::exception& e)
	  {
	    OPENVPN_LOG("Error parsing client-ip: " << e.what());
	  }
	ev->tun_name = tun->tun_name();
	cli_events->add_event(ev);
	connected_ = true;
	if (notify_callback)
	  notify_callback->client_proto_connected();
      }

      virtual void tun_error(const std::exception& err)
      {
	fatal_ = Error::TUN_SETUP_FAILED;
	fatal_reason_ = err.what();
	if (notify_callback)
	  {
	    OPENVPN_LOG("TUN Error: " << err.what());
	    stop(true);
	  }
	else
	  throw tun_exception(err.what());
      }

      // proto base class calls here to get auth credentials
      virtual void client_auth(Buffer& buf)
      {
	if (creds)
	  {
	    Base::write_auth_string(creds->get_username(), buf);
	    Base::write_auth_string(creds->get_password(), buf);
	  }
	else
	  {
	    Base::write_empty_string(buf); // username
	    Base::write_empty_string(buf); // password
	  }
      }

      void send_push_request_callback(const boost::system::error_code& e)
      {
	try {
	  if (!e && !halt && !received_options.partial())
	    {
	      Base::update_now();
	      if (!sent_push_request)
		{
		  ClientEvent::Base::Ptr ev = new ClientEvent::GetConfig();
		  cli_events->add_event(ev);
		  sent_push_request = true;
		}
	      OPENVPN_LOG("Sending PUSH_REQUEST to server...");
	      Base::write_control_string(std::string("PUSH_REQUEST"));
	      Base::flush(true);
	      set_housekeeping_timer();
	      schedule_push_request_callback(false);
	    }
	}
	catch (const std::exception& e)
	  {
	    process_exception(e, "send_push_request_callback");
	  }
      }

      void schedule_push_request_callback(bool short_time)
      {
	if (!received_options.partial())
	  {
	    push_request_timer.expires_at(now() + (short_time ? Time::Duration::seconds(1) : Time::Duration::seconds(3)));
	    push_request_timer.async_wait(asio_dispatch_timer(&Session::send_push_request_callback, this));
	  }
      }

      // base class calls here when primary session transitions to ACTIVE state
      virtual void active()
      {
	OPENVPN_LOG("Session is ACTIVE");
	schedule_push_request_callback(true);
      }

      void housekeeping_callback(const boost::system::error_code& e)
      {
	try {
	  if (!e && !halt)
	    {
	      // update current time
	      Base::update_now();

	      housekeeping_schedule.reset();
	      Base::housekeeping();
	      if (Base::invalidated())
		{
		  if (notify_callback)
		    {
		      OPENVPN_LOG("Session invalidated");
		      stop(true);
		    }
		  else
		    throw session_invalidated();
		}
	      set_housekeeping_timer();
	    }
	}
	catch (const std::exception& e)
	  {
	    process_exception(e, "housekeeping_callback");
	  }
      }

      void set_housekeeping_timer()
      {
	Time next = Base::next_housekeeping();
	if (!housekeeping_schedule.similar(next))
	  {
	    if (!next.is_infinite())
	      {
		next.max(now());
		housekeeping_schedule.reset(next);
		housekeeping_timer.expires_at(next);
		housekeeping_timer.async_wait(asio_dispatch_timer(&Session::housekeeping_callback, this));
	      }
	    else
	      {
		housekeeping_timer.cancel();
	      }
	  }
      }

      void process_exception(const std::exception& e, const char *method_name)
      {
	if (notify_callback)
	  {
	    OPENVPN_LOG("Client exception in " << method_name << ": " << e.what());
	    stop(true);
	  }
	else
	  throw client_exception(e.what());
      }

      void process_halt_restart(const ClientHalt& ch)
      {
	if (ch.restart() && (ch.psid() || !creds || !creds->password_defined()))
	  fatal_ = Error::CLIENT_RESTART;
	else
	  fatal_ = Error::CLIENT_HALT;
	fatal_reason_ = ch.reason();
	if (notify_callback)
	  {
	    OPENVPN_LOG("Client halt/restart: " << ch.render());
	    stop(true);
	  }
	else
	  throw client_halt_restart(ch.render());
      }

#ifdef OPENVPN_PACKET_LOG
      void log_packet(const Buffer& buf, const bool out)
      {
	if (buf.size())
	  {
	    boost::uint16_t len = buf.size() & 0x7FFF;
	    if (out)
	      len |= 0x8000;
	    packet_log.write((const char *)&len, sizeof(len));
	    packet_log.write((const char *)buf.c_data(), buf.size());
	  }
      }
#endif

      boost::asio::io_service& io_service;

      TransportClientFactory::Ptr transport_factory;
      TransportClient::Ptr transport;

      TunClientFactory::Ptr tun_factory;
      TunClient::Ptr tun;

      NotifyCallback* notify_callback;

      CoarseTime housekeeping_schedule;
      AsioTimer housekeeping_timer;
      AsioTimer push_request_timer;
      bool halt;

      OptionListContinuation received_options;

      ClientCreds::Ptr creds;

      ProtoContextOptions::Ptr proto_context_options;

      bool first_packet_received_;
      bool sent_push_request;
      ClientEvent::Queue::Ptr cli_events;

      bool connected_;

      Error::Type fatal_;
      std::string fatal_reason_;

      const unsigned int max_pushed_options;

#ifdef OPENVPN_PACKET_LOG
      std::ofstream packet_log;
#endif
    };
  }
}

#endif
