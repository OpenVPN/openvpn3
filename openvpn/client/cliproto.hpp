#ifndef OPENVPN_CLIENT_CLIPROTO_H
#define OPENVPN_CLIENT_CLIPROTO_H

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/cstdint.hpp> // for boost::uint...
#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with

#include <openvpn/common/rc.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/options/continuation.hpp>
#include <openvpn/client/clievent.hpp>
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

    template <typename SSL_CONTEXT>
    class Session : public ProtoContext<SSL_CONTEXT>, TransportClientParent, TunClientParent
    {
      typedef ProtoContext<SSL_CONTEXT> Base;
      typedef typename Base::PacketType PacketType;

      using Base::now;

    public:
      typedef boost::intrusive_ptr<Session> Ptr;
      typedef typename Base::Config ProtoConfig;

      OPENVPN_EXCEPTION(client_exception);
      OPENVPN_EXCEPTION(tun_exception);
      OPENVPN_EXCEPTION(transport_exception);
      OPENVPN_SIMPLE_EXCEPTION(session_invalidated);
      OPENVPN_SIMPLE_EXCEPTION(authentication_failed);

      struct Config : public RC<thread_unsafe_refcount>
      {
	typedef boost::intrusive_ptr<Config> Ptr;

	typename Base::Config::Ptr proto_context_config;
	TransportClientFactory::Ptr transport_factory;
	TunClientFactory::Ptr tun_factory;
	SessionStats::Ptr cli_stats;
	ClientEvent::Queue::Ptr cli_events;
	std::string username;
	std::string password;
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
	  username(config.username),
	  password(config.password),
	  first_packet_received_(false),
	  sent_push_request(false),
	  cli_events(config.cli_events),
	  connected_(false),
	  auth_failed_(false)
      {
#ifdef OPENVPN_PACKET_LOG
	packet_log.open(OPENVPN_PACKET_LOG, std::ios::binary);
	if (!packet_log)
	  OPENVPN_THROW(open_file_error, "cannot open packet log for output: " << OPENVPN_PACKET_LOG);
#endif
      }

      bool first_packet_received() const { return first_packet_received_; }

      void start()
      {
	if (!halt)
	  {
	    // coarse wakeup range
	    housekeeping_schedule.init(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024));

	    // initialize transport-layer packet handler
	    transport = transport_factory->new_client_obj(io_service, *this);
	    transport->start();
	  }
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

      bool auth_failed() const { return auth_failed_; }

      virtual ~Session()
      {
	stop(false);
      }

    private:
      // transport obj calls here with incoming packets
      virtual void transport_recv(BufferAllocated& buf)
      {
	try {
	  OPENVPN_LOG_CLIPROTO("Transport recv " << Base::dump_packet(buf));

	  // update current time
	  Base::update_now();

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
	catch (std::exception& e)
	  {
	    process_exception(e);
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
	      OPENVPN_LOG_CLIPROTO("Transport send " << Base::dump_packet(buf));
	      if (transport->transport_send(buf))
		Base::update_last_sent();
	    }

	  // do a lightweight flush
	  Base::flush(false);

	  // schedule housekeeping wakeup
	  set_housekeeping_timer();
	}
	catch (std::exception& e)
	  {
	    process_exception(e);
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
	catch (std::exception& e)
	  {
	    process_exception(e);
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
	    password = (*o)[1];
	    OPENVPN_LOG("using session token " << password);
	  }
      }

      // proto base class calls here for control channel network sends
      virtual void control_net_send(const Buffer& net_buf)
      {
	OPENVPN_LOG_CLIPROTO("Transport send " << Base::dump_packet(net_buf));
	if (transport->transport_send_const(net_buf))
	  Base::update_last_sent();
      }

      // proto base class calls here for app-level control-channel messages received
      virtual void control_recv(BufferPtr& app_bp)
      {
	const std::string msg = Base::template read_control_string<std::string>(*app_bp);
	OPENVPN_LOG("SERVER: " << msg);
	if (!received_options.complete() && boost::starts_with(msg, "PUSH_REPLY,"))
	  {
	    // parse the received options
	    received_options.add(OptionList::parse_from_csv(msg.substr(11)));
	    if (received_options.complete())
	      {
		// show options
		OPENVPN_LOG(received_options.debug_render());

		// process auth-token
		extract_auth_token(received_options);

		// modify proto config (cipher, auth, and compression methods)
		Base::process_push(received_options);

		// initialize tun/routing
		tun = tun_factory->new_client_obj(io_service, *this);
		tun->client_start(received_options, *transport);
	      }
	    else
	      OPENVPN_LOG("Options continuation...");
	  }
	else if (boost::starts_with(msg, "AUTH_FAILED"))
	  {
	    auth_failed_ = true;
	    Base::stat().error(Error::AUTH_FAILED);
	    if (notify_callback)
	      {
		OPENVPN_LOG("AUTH_FAILED");
		stop(true);
	      }
	    else
	      throw authentication_failed();
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
	ev->user = username;
	transport->server_endpoint_info(ev->server_host, ev->server_port, ev->server_proto, ev->server_ip);
	ev->vpn_ip = tun->vpn_ip();
	ev->tun_name = tun->tun_name();
	cli_events->add_event(ev);
	connected_ = true;
	if (notify_callback)
	  notify_callback->client_proto_connected();
      }

      virtual void tun_error(const std::exception& err)
      {
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
	Base::write_auth_string(username, buf);
	Base::write_auth_string(password, buf);
      }

      void send_push_request_callback(const boost::system::error_code& e)
      {
	try {
	  if (!e && !received_options.partial())
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
	catch (std::exception& e)
	  {
	    process_exception(e);
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
	  if (!e)
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
	catch (std::exception& e)
	  {
	    process_exception(e);
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

      void process_exception(std::exception& e)
      {
	if (notify_callback)
	  {
	    OPENVPN_LOG("Client exception: " << e.what());
	    stop(true);
	  }
	else
	  throw client_exception(e.what());
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

      std::string username;
      std::string password;

      bool first_packet_received_;
      bool sent_push_request;
      ClientEvent::Queue::Ptr cli_events;

      bool connected_;
      bool auth_failed_;

#ifdef OPENVPN_PACKET_LOG
      std::ofstream packet_log;
#endif
    };
  }
}

#endif
