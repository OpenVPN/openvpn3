//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_OMI_OMI_H
#define OPENVPN_OMI_OMI_H

#include <string>
#include <sstream>
#include <vector>
#include <deque>
#include <memory>
#include <utility>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/buffer/bufstr.hpp>

// include acceptors for different protocols
#include <openvpn/acceptor/base.hpp>
#include <openvpn/acceptor/tcp.hpp>
#ifdef ASIO_HAS_LOCAL_SOCKETS
#include <openvpn/acceptor/unix.hpp>
#endif

namespace openvpn {
  class OMICore : public Acceptor::ListenerBase
  {
  public:
    OPENVPN_EXCEPTION(omi_error);

    struct Command {
      Option option;
      std::vector<std::string> extra;
      bool valid_utf8 = false;

      std::string to_string() const
      {
	std::ostringstream os;
	os << option.render(Option::RENDER_BRACKET);
	if (!valid_utf8)
	  os << " >>>!UTF8";
	os << '\n';
	for (auto &line : extra)
	  os << line << '\n';
	return os.str();
      }
    };

    OMICore(asio::io_context& io_context_arg,
	    OptionList opt_arg)
      : io_context(io_context_arg),
	opt(std::move(opt_arg))
    {
    }

    void open_log()
    {
      // open log file
	const std::string log_fn = opt.get_optional("log", 1, 256);
	if (!log_fn.empty())
	  log_setup(log_fn);
    }

    std::string get_config() const
    {
      // get config file
      const std::string config_fn = opt.get("config", 1, 256);
      return read_config(config_fn);
    }

    void start()
    {
      const Option& o = opt.get("management");
      const std::string addr = o.get(1, 256);
      const std::string port = o.get(2, 16);
      if (opt.exists("management-client"))
	{
	  if (port == "unix")
	    {
	      OPENVPN_LOG("Connecting to " << addr << " [unix]");
	      connect_unix(addr);
	    }
	  else
	    {
	      OPENVPN_LOG("Connecting to [" << addr << "]:" << port << " [tcp]");
	      connect_tcp(addr, port);
	    }
	}
      else
	{
	  if (port == "unix")
	    {
	      OPENVPN_LOG("Listening on " << addr << " [unix]");
	      listen_unix(addr);
	    }
	  else
	    {
	      OPENVPN_LOG("Listening on [" << addr << "]:" << port << " [tcp]");
	      listen_tcp(addr, port);
	    }
	}
    }

    void stop()
    {
      if (halt)
	return;
      halt = true;

      // close acceptor
      if (acceptor)
	acceptor->close();

      // close client socket
      stop_client(false);
    }

  protected:
    void send(BufferPtr buf)
    {
      if (halt || !is_sock_open())
	return;
      content_out.push_back(std::move(buf));
      if (content_out.size() == 1) // send operation not currently active?
	queue_send();
    }

    void send(const std::string& str)
    {
      send(buf_from_string(str));
    }

    virtual bool omi_command_is_multiline(const Option& option) = 0;
    virtual void omi_command_in(std::unique_ptr<Command> cmd) = 0;
    virtual void omi_done(const bool eof) = 0;

    asio::io_context& io_context;
    const OptionList opt;
    bool halt = false;

  private:
    typedef RCPtr<OMICore> Ptr;

    bool is_sock_open() const
    {
      return socket && socket->is_open();
    }

    void stop_client(const bool eof)
    {
      if (is_sock_open())
	socket->close();
      content_out.clear();
      in_partial.clear();
      omi_done(eof);
    }

    void send_title_message()
    {
      send(">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info\n");
    }

    void process_in_line() // process incoming line in in_partial
    {
      const bool utf8 = Unicode::is_valid_utf8(in_partial);
      string::trim_crlf(in_partial);
      if (multiline)
	{
	  if (!command)
	    throw omi_error("process_in_line: internal error");
	  if (in_partial == "END")
	    {
	      omi_command_in(std::move(command));
	      command.reset();
	      multiline = false;
	    }
	  else
	    {
	      if (!utf8)
		command->valid_utf8 = false;
	      command->extra.push_back(std::move(in_partial));
	    }
	}
      else
	{
	  command.reset(new Command);
	  command->option = OptionList::parse_option_from_line(in_partial, nullptr);
	  command->valid_utf8 = utf8;
	  multiline = omi_command_is_multiline(command->option);
	  if (!multiline)
	    {
	      omi_command_in(std::move(command));
	      command.reset();
	    }
	}
    }

    static std::string read_config(const std::string& fn)
    {
      if (fn == "stdin")
	return read_stdin();
      else
	return read_text_utf8(fn);
    }

    void log_setup(const std::string& log_fn)
    {
#if defined(OPENVPN_PLATFORM_WIN)
      // fixme -- code for Windows
#else
      RedirectStd redir("",
			log_fn,
			RedirectStd::FLAGS_OVERWRITE,
			RedirectStd::MODE_ALL,
			false);
      redir.redirect();
#endif
    }

    void listen_tcp(const std::string& addr, const std::string& port)
    {
      // init TCP acceptor
      Acceptor::TCP::Ptr a(new Acceptor::TCP(io_context));

      // parse address/port of local endpoint
      const IP::Addr ip_addr = IP::Addr::from_string(addr);
      a->local_endpoint.address(ip_addr.to_asio());
      a->local_endpoint.port(HostPort::parse_port(port, "tcp listen"));

      // open socket
      a->acceptor.open(a->local_endpoint.protocol());

      // set options
      a->set_socket_options();

      // bind to local address
      a->acceptor.bind(a->local_endpoint);

      // listen for incoming client connections
      a->acceptor.listen();

      // save acceptor
      acceptor = a;

      // dispatch accepts to handle_except()
      queue_accept();
    }

    void listen_unix(const std::string& socket_path)
    {
#ifdef ASIO_HAS_LOCAL_SOCKETS
      // init unix socket acceptor
      Acceptor::Unix::Ptr a(new Acceptor::Unix(io_context));

      // set endpoint
      a->pre_listen(socket_path);
      a->local_endpoint.path(socket_path);

      // open socket
      a->acceptor.open(a->local_endpoint.protocol());

      // bind to local address
      a->acceptor.bind(a->local_endpoint);

      // set socket permissions in filesystem
      a->set_socket_permissions(socket_path, 0777);

      // listen for incoming client connections
      a->acceptor.listen();

      // save acceptor
      acceptor = a;

      // dispatch accepts to handle_except()
      queue_accept();
#else
      throw Exception("unix sockets not supported on this platform");
#endif
    }

    void queue_accept()
    {
      acceptor->async_accept(this, 0, io_context);
    }

    virtual void handle_accept(AsioPolySock::Base::Ptr sock, const asio::error_code& error) override
    {
      if (halt)
	return;

      try {
	if (error)
	  throw Exception("accept failed: " + error.message());
	if (is_sock_open())
	  throw Exception("client already connected");

	sock->non_blocking(true);
	sock->set_cloexec();
	socket = std::move(sock);

	send_title_message();
	queue_recv();
      }
      catch (const std::exception& e)
	{
	  std::cerr << "exception in handle_accept: " << e.what() << std::endl;
	}
      queue_accept();
    }

    void connect_tcp(const std::string& addr, const std::string& port)
    {
    }

    void connect_unix(const std::string& socket_path)
    {
    }

    void queue_recv()
    {
      if (halt || !is_sock_open())
	return;
      BufferPtr buf(new BufferAllocated(256, 0));
      socket->async_receive(buf->mutable_buffers_1_clamp(),
			    [self=Ptr(this), sock=socket, buf](const asio::error_code& error, const size_t bytes_recvd)
			    {
			      self->handle_recv(error, bytes_recvd, *buf, sock.get());
			    });
    }

    void handle_recv(const asio::error_code& error, const size_t bytes_recvd,
		     Buffer& buf, const AsioPolySock::Base* queued_socket)
    {
      if (halt || !is_sock_open() || socket.get() != queued_socket)
	return;
      if (error)
	{
	  const bool eof = (error == asio::error::eof);
	  if (!eof)
	    OPENVPN_LOG("client socket recv error: " << error.message());
	  stop_client(eof);
	  return;
	}
      buf.set_size(bytes_recvd);

      while (buf.size())
	{
	  const char c = (char)buf.pop_front();
	  in_partial += c;
	  if (c == '\n')
	    {
	      try {
		process_in_line();
	      }
	      catch (const std::exception& e)
		{
		  OPENVPN_LOG("error processing omi command: " << e.what());
		  stop_client(false);
		  return;
		}
	      in_partial.clear();
	    }
	}

      queue_recv();
    }

    void queue_send()
    {
      if (halt || !is_sock_open())
	return;
      BufferAllocated& buf = *content_out.front();
      socket->async_send(buf.const_buffers_1_clamp(),
			 [self=Ptr(this), sock=socket](const asio::error_code& error, const size_t bytes_sent)
			 {
			   self->handle_send(error, bytes_sent, sock.get());
			 });
    }

    void handle_send(const asio::error_code& error, const size_t bytes_sent,
		     const AsioPolySock::Base* queued_socket)
    {
      if (halt || !is_sock_open() || socket.get() != queued_socket)
	return;

      if (error)
	{
	  OPENVPN_LOG("client socket send error: " << error.message());
	  stop_client(false);
	  return;
	}

      BufferPtr buf = content_out.front();
      if (bytes_sent == buf->size())
	content_out.pop_front();
      else if (bytes_sent < buf->size())
	buf->advance(bytes_sent);
      else
	{
	  OPENVPN_LOG("client socket unexpected send size: " << bytes_sent << '/' << buf->size());
	  stop_client(false);
	  return;
	}

      if (!content_out.empty())
	queue_send();
    }

    Acceptor::Base::Ptr acceptor;
    AsioPolySock::Base::Ptr socket;
    std::deque<BufferPtr> content_out;
    std::string in_partial;
    std::unique_ptr<Command> command;
    bool multiline = false;
  };
}

#endif
