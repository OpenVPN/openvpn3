#ifndef OPENVPN_CLIENT_CLIPROTO_H
#define OPENVPN_CLIENT_CLIPROTO_H

#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

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

  // OpenVPN client
  template <typename SSL_CONTEXT>
  class ClientProto : public ProtoContext<SSL_CONTEXT>, TransportClientParent, TunClientParent
  {
    typedef ProtoContext<SSL_CONTEXT> Base;
    typedef typename Base::PacketType PacketType;

    using Base::now;

  public:
    typedef boost::intrusive_ptr<ClientProto> Ptr;

    OPENVPN_EXCEPTION(client_exception);
    OPENVPN_EXCEPTION(tun_exception);
    OPENVPN_EXCEPTION(transport_exception);
    OPENVPN_SIMPLE_EXCEPTION(session_invalidated);
    OPENVPN_SIMPLE_EXCEPTION(auth_failed);

    ClientProto(boost::asio::io_service& io_service_arg,
		const typename Base::Config::Ptr& config,
		const TransportClientFactory::Ptr& transport_factory_arg,
		const TunClientFactory::Ptr& tun_factory_arg,
		const SessionStats::Ptr& stats_arg,
		const ClientEvent::Queue::Ptr& cli_events_arg,
		const bool client_throw_arg,
		const std::string& username_arg,
		const std::string& password_arg)
      : Base(config, stats_arg),
	io_service(io_service_arg),
	transport_factory(transport_factory_arg),
	tun_factory(tun_factory_arg),
	client_throw(client_throw_arg),
	housekeeping_timer(io_service_arg),
	push_request_timer(io_service_arg),
	stopped(false),
	username(username_arg),
	password(password_arg),
	first_packet_received(false),
	sent_push_request(false),
	cli_events(cli_events_arg)
    {
#ifdef OPENVPN_PACKET_LOG
      packet_log.open(OPENVPN_PACKET_LOG, std::ios::binary);
      if (!packet_log)
	OPENVPN_THROW(open_file_error, "cannot open packet log for output: " << OPENVPN_PACKET_LOG);
#endif
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

    void start()
    {
      // coarse wakeup range
      housekeeping_schedule.init(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024));

      // initialize transport-layer packet handler
      transport = transport_factory->new_client_obj(io_service, *this);
      transport->start();
    }

    void stop_on_signal(const boost::system::error_code& error, int signal_number)
    {
      stop();
    }

    void stop()
    {
      if (!stopped)
	{
	  housekeeping_timer.cancel();
	  push_request_timer.cancel();
	  if (tun)
	    tun->stop();
	  if (transport)
	    transport->stop();
	  stopped = true;
	}
    }

    virtual ~ClientProto()
    {
      stop();
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
	if (!first_packet_received)
	  {
	    ClientEvent::Base::Ptr ev = new ClientEvent::Connecting();
	    cli_events->add_event(ev);
	    first_packet_received = true;
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
      if (client_throw)
	throw transport_exception(err.what());
      else
	{
	  OPENVPN_LOG("Transport Error: " << err.what());
	  stop();
	}
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
	  Base::stat().error(Error::AUTH_FAIL);
	  if (client_throw)
	    throw auth_failed();
	  else
	    {
	      OPENVPN_LOG("AUTH_FAILED");
	      stop();
	    }
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
    }

    virtual void tun_error(const std::exception& err)
    {
      if (client_throw)
	throw tun_exception(err.what());
      else
	{
	  OPENVPN_LOG("TUN Error: " << err.what());
	  stop();
	}
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
	  push_request_timer.async_wait(asio_dispatch_timer(&ClientProto::send_push_request_callback, this));
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
		if (client_throw)
		  throw session_invalidated();
		else
		  {
		    OPENVPN_LOG("Session invalidated");
		    stop();
		  }
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
	      housekeeping_timer.async_wait(asio_dispatch_timer(&ClientProto::housekeeping_callback, this));
	    }
	  else
	    {
	      housekeeping_timer.cancel();
	    }
	}
    }

    void process_exception(std::exception& e)
    {
      if (client_throw)
	throw client_exception(e.what());
      else
	{
	  OPENVPN_LOG("Client exception: " << e.what());
	  stop();
	}
    }

    boost::asio::io_service& io_service;

    TransportClientFactory::Ptr transport_factory;
    TransportClient::Ptr transport;

    TunClientFactory::Ptr tun_factory;
    TunClient::Ptr tun;

    bool client_throw;

    CoarseTime housekeeping_schedule;
    AsioTimer housekeeping_timer;
    AsioTimer push_request_timer;
    bool stopped;

    OptionListContinuation received_options;

    std::string username;
    std::string password;

    bool first_packet_received;
    bool sent_push_request;
    ClientEvent::Queue::Ptr cli_events;

#ifdef OPENVPN_PACKET_LOG
    std::ofstream packet_log;
#endif
  };
}

#endif
