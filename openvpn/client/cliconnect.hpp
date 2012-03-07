#ifndef OPENVPN_CLIENT_CLICONNECT_H
#define OPENVPN_CLIENT_CLICONNECT_H

#include <openvpn/common/rc.hpp>
#include <openvpn/client/cliopt.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/common/scoped_ptr.hpp>

namespace openvpn {

  // ClientConnect implements an "always-try-to-reconnect" approach, with remote
  // list rotation.  Only gives up on auth failure.
  struct ClientConnect : ClientProto::NotifyCallback, public RC<thread_safe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientConnect> Ptr;
    typedef ClientOptions::Client Client;

    OPENVPN_SIMPLE_EXCEPTION(client_connect_unhandled_exception);

    ClientConnect(boost::asio::io_service& io_service_arg,
		  const ClientOptions::Ptr& client_options_arg)
      : generation(0),
	halt(false),
	paused(false),
	conn_timeout(client_options_arg->conn_timeout()),
	io_service(io_service_arg),
	client_options(client_options_arg),
	server_poll_timer(io_service_arg),
	restart_wait_timer(io_service_arg),
	conn_timer(io_service_arg),
	conn_timer_pending(false)
    {
    }

    void start()
    {
      if (!client && !halt)
	new_client();
    }

    void graceful_stop()
    {
      if (!halt && client)
	  client->send_explicit_exit_notify();
      stop();
    }

    void stop()
    {
      if (!halt)
	{
	  halt = true;
	  if (client)
	    client->stop(false);
	  cancel_timers();
	  asio_work.reset();
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
	io_service.post(asio_dispatch_post(&ClientConnect::graceful_stop, this));
    }

    void pause()
    {
      if (!halt && !paused)
	{
	  paused = true;
	  if (client)
	    {
	      client->send_explicit_exit_notify();
	      client->stop(false);
	    }
	  cancel_timers();
	  asio_work.reset(new boost::asio::io_service::work(io_service));
	  ClientEvent::Base::Ptr ev = new ClientEvent::Pause();
	  client_options->events().add_event(ev);
	}
    }

    void resume()
    {
      if (!halt && paused)
	{
	  paused = false;
	  ClientEvent::Base::Ptr ev = new ClientEvent::Resume();
	  client_options->events().add_event(ev);
	  new_client();
	}
    }

    void reconnect(int seconds)
    {
      if (!halt)
	{
	  if (seconds < 0)
	    seconds = 0;
	  OPENVPN_LOG("Client terminated, reconnecting in " << seconds << "...");
	  server_poll_timer.cancel();
	  restart_wait_timer.expires_at(Time::now() + Time::Duration::seconds(seconds));
	  restart_wait_timer.async_wait(asio_dispatch_timer_arg(&ClientConnect::restart_wait_callback, this, generation));
	}
    }

    void thread_safe_pause()
    {
      if (!halt)
	io_service.post(asio_dispatch_post(&ClientConnect::pause, this));
    }

    void thread_safe_resume()
    {
      if (!halt)
	io_service.post(asio_dispatch_post(&ClientConnect::resume, this));
    }

    void thread_safe_reconnect(int seconds)
    {
      if (!halt)
	io_service.post(asio_dispatch_post_arg(&ClientConnect::reconnect, this, seconds));
    }

    ~ClientConnect()
    {
      stop();
    }

  private:
    void cancel_timers()
    {
      restart_wait_timer.cancel();
      server_poll_timer.cancel();
      conn_timer.cancel();
      conn_timer_pending = false;
    }

    void restart_wait_callback(unsigned int gen, const boost::system::error_code& e)
    {
      if (!e && gen == generation && !halt)
	{
	  if (paused)
	    resume();
	  else
	    new_client();
	}
    }

    void server_poll_callback(unsigned int gen, const boost::system::error_code& e)
    {
      if (!e && gen == generation && !halt && !client->first_packet_received())
	{
	  OPENVPN_LOG("Server poll timeout, trying next remote entry...");
	  new_client();
	}
    }

    void conn_timer_callback(unsigned int gen, const boost::system::error_code& e)
    {
      if (!e && !halt)
	{
	  ClientEvent::Base::Ptr ev = new ClientEvent::ConnectionTimeout();
	  client_options->events().add_event(ev);
	  client_options->stats().error(Error::CONNECTION_TIMEOUT);
	  stop();
	}
    }

    void conn_timer_start()
    {
      if (!conn_timer_pending && conn_timeout > 0)
	{
	  conn_timer.expires_at(Time::now() + Time::Duration::seconds(conn_timeout));
	  conn_timer.async_wait(asio_dispatch_timer_arg(&ClientConnect::conn_timer_callback, this, generation));
	  conn_timer_pending = true;
	}
    }

    virtual void client_proto_connected()
    {
      conn_timer.cancel();
      conn_timer_pending = false;
    }

    virtual void client_proto_terminate()
    {
      if (!halt)
	{
	  switch (client->fatal())
	    {
	    case Error::SUCCESS: // doesn't necessarily mean success, just that there wasn't a fatal error
	      {
		const unsigned int delay = 2;
		OPENVPN_LOG("Client terminated, restarting in " << delay << "...");
		server_poll_timer.cancel();
		restart_wait_timer.expires_at(Time::now() + Time::Duration::seconds(delay));
		restart_wait_timer.async_wait(asio_dispatch_timer_arg(&ClientConnect::restart_wait_callback, this, generation));
	      }
	      break;
	    case Error::AUTH_FAILED:
	      {
		const std::string& reason = client->fatal_reason();
		if (ChallengeResponse::is_dynamic(reason)) // dynamic challenge/reponse?
		  {
		    ClientEvent::Base::Ptr ev = new ClientEvent::DynamicChallenge(reason);
		    client_options->events().add_event(ev);
		  }
		else
		  {
		    ClientEvent::Base::Ptr ev = new ClientEvent::AuthFailed(reason);
		    client_options->events().add_event(ev);
		    client_options->stats().error(Error::AUTH_FAILED);
		  }
		stop();
	      }
	      break;
	    case Error::TUN_SETUP_FAILED:
	      {
		ClientEvent::Base::Ptr ev = new ClientEvent::TunSetupFailed(client->fatal_reason());
		client_options->events().add_event(ev);
		stop();
	      }
	      break;
	    default:
	      throw client_connect_unhandled_exception();
	    }
	}
    }

    void new_client()
    {
      ++generation;
      asio_work.reset();
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
      conn_timer_start();
      client->start();
    }

    unsigned int generation;
    bool halt;
    bool paused;
    int conn_timeout;
    boost::asio::io_service& io_service;
    ClientOptions::Ptr client_options;
    Client::Ptr client;
    AsioTimer server_poll_timer;
    AsioTimer restart_wait_timer;
    AsioTimer conn_timer;
    bool conn_timer_pending;
    ScopedPtr<boost::asio::io_service::work> asio_work;
  };

}

#endif
