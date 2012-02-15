#ifndef OPENVPN_CLIENT_CLICONNECT_H
#define OPENVPN_CLIENT_CLICONNECT_H

#include <openvpn/common/rc.hpp>
#include <openvpn/client/cliopt.hpp>
#include <openvpn/time/asiotimer.hpp>

namespace openvpn {

  // ClientConnect implements an "always-try-to-reconnect" approach, with remote
  // list rotation.  Only gives up on auth failure.
  struct ClientConnect : ClientProto::NotifyCallback, public RC<thread_safe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientConnect> Ptr;
    typedef ClientOptions::Client Client;

    ClientConnect(boost::asio::io_service& io_service_arg,
		  const ClientOptions::Ptr& client_options_arg)
      : generation(0),
	halt(false),
	io_service(io_service_arg),
	client_options(client_options_arg),
	server_poll_timer(io_service_arg),
	restart_wait_timer(io_service_arg)
    {
    }

    void start()
    {
      if (!client && !halt)
	new_client();
    }

    void stop()
    {
      if (!halt)
	{
	  halt = true;
	  if (client)
	    client->stop(false);
	  restart_wait_timer.cancel();
	  server_poll_timer.cancel();
	  ClientEvent::Base::Ptr ev = new ClientEvent::Disconnected();
	  client_options->events().add_event(ev);
	}
    }

    void stop_on_signal(const boost::system::error_code& error, int signal_number)
    {
      stop();
    }

    // like stop() but may be safely called by another thread
    void thread_safe_stop()
    {
      if (!halt)
	io_service.post(asio_dispatch_post(&ClientConnect::stop, this));
    }

    ~ClientConnect()
    {
      stop();
    }

  private:
    void restart_wait_callback(unsigned int gen, const boost::system::error_code& e)
    {
      if (!e && gen == generation && !halt)
	new_client();
    }

    void server_poll_callback(unsigned int gen, const boost::system::error_code& e)
    {
      if (!e && gen == generation && !halt && !client->first_packet_received())
	{
	  OPENVPN_LOG("Server poll timeout, trying next remote entry...");
	  new_client();
	}
    }

    virtual void client_proto_terminate()
    {
      if (!halt)
	{
	  if (client->auth_failed())
	    {
	      ClientEvent::Base::Ptr ev = new ClientEvent::AuthFailed(client->auth_failed_reason());
	      client_options->events().add_event(ev);
	      client_options->stats().error(Error::AUTH_FAILED);
	      stop();
	    }
	  else
	    {
	      const unsigned int delay = 2;
	      OPENVPN_LOG("Client terminated, restarting in " << delay << "...");
	      server_poll_timer.cancel();
	      restart_wait_timer.expires_at(Time::now() + Time::Duration::seconds(delay));
	      restart_wait_timer.async_wait(asio_dispatch_timer_arg(&ClientConnect::restart_wait_callback, this, generation));
	    }
	}
    }

    void new_client()
    {
      ++generation;
      if (client)
	client->stop(false);
      if (generation > 1)
	{
	  ClientEvent::Base::Ptr ev = new ClientEvent::Reconnecting();
	  client_options->events().add_event(ev);
	  if (!(client && client->reached_connected_state()))
	    client_options->next();
	}
      Client::Config::Ptr cli_config = client_options->client_config();
      client.reset(new Client(io_service, *cli_config, this));
      restart_wait_timer.cancel();
      server_poll_timer.expires_at(Time::now() + client_options->server_poll_timeout());
      server_poll_timer.async_wait(asio_dispatch_timer_arg(&ClientConnect::server_poll_callback, this, generation));
      client->start();
    }

    unsigned int generation;
    bool halt;
    boost::asio::io_service& io_service;
    ClientOptions::Ptr client_options;
    Client::Ptr client;
    AsioTimer server_poll_timer;
    AsioTimer restart_wait_timer;
  };

}

#endif
