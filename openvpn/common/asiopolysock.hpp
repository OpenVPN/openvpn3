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

// Asio polymorphic socket for handling TCP
// and unix domain sockets.

#ifndef OPENVPN_COMMON_ASIOPOLYSOCK_H
#define OPENVPN_COMMON_ASIOPOLYSOCK_H

#include <asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/function.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/sockopt.hpp>
#include <openvpn/addr/ip.hpp>

#ifdef ASIO_HAS_LOCAL_SOCKETS
#include <openvpn/common/peercred.hpp>
#endif

namespace openvpn {
  namespace AsioPolySock {
    class Base : public RC<thread_unsafe_refcount>
    {
    public:
      typedef RCPtr<Base> Ptr;

      virtual void async_send(const asio::const_buffers_1& buf,
			      Function<void(const asio::error_code&, const size_t)>&& callback) = 0;

      virtual void async_receive(const asio::mutable_buffers_1& buf,
				 Function<void(const asio::error_code&, const size_t)>&& callback) = 0;

      virtual std::string remote_endpoint_str() const = 0;
      virtual bool remote_ip_port(IP::Addr& addr, unsigned int& port) const = 0;

      virtual void non_blocking(const bool state) = 0;

      virtual void close() = 0;

      virtual void tcp_nodelay() {}
      virtual void set_cloexec() {}

#ifdef ASIO_HAS_LOCAL_SOCKETS
      virtual bool peercreds(SockOpt::Creds& cr)
      {
	return false;
      }
#endif

      virtual bool is_local() const = 0;

      size_t index() const { return index_; }

    protected:
      Base(const size_t index)
	: index_(index)
      {
      }

    private:
      size_t index_;
    };

    struct TCP : public Base
    {
      typedef RCPtr<TCP> Ptr;

      TCP(asio::io_context& io_context,
	  const size_t index)
	:  Base(index),
	   socket(io_context)
      {
      }

      virtual void async_send(const asio::const_buffers_1& buf,
			      Function<void(const asio::error_code&, const size_t)>&& callback) override
      {
	socket.async_send(buf, std::move(callback));
      }

      virtual void async_receive(const asio::mutable_buffers_1& buf,
				 Function<void(const asio::error_code&, const size_t)>&& callback) override
      {
	socket.async_receive(buf, std::move(callback));
      }

      virtual std::string remote_endpoint_str() const override
      {
	return to_string(socket.remote_endpoint());
      }

      virtual bool remote_ip_port(IP::Addr& addr, unsigned int& port) const override
      {
	try {
	  addr = IP::Addr::from_asio(socket.remote_endpoint().address());
	  port = socket.remote_endpoint().port();
	  return true;
	}
	catch (std::exception&)
	  {
	    return false;
	  }
      }

      virtual void non_blocking(const bool state) override
      {
	socket.non_blocking(state);
      }

      virtual void tcp_nodelay() override
      {
	socket.set_option(asio::ip::tcp::no_delay(true));
      }

#if !defined(OPENVPN_PLATFORM_WIN)
      virtual void set_cloexec() override
      {
	SockOpt::set_cloexec(socket.native_handle());
      }
#endif

      virtual void close() override
      {
	socket.close();
      }

      virtual bool is_local() const override
      {
	return false;
      }

      asio::ip::tcp::socket socket;
    };

#ifdef ASIO_HAS_LOCAL_SOCKETS
    struct Unix : public Base
    {
      typedef RCPtr<Unix> Ptr;

      Unix(asio::io_context& io_context,
	   const size_t index)
	:  Base(index),
	   socket(io_context)
      {
      }

      virtual void async_send(const asio::const_buffers_1& buf,
			      Function<void(const asio::error_code&, const size_t)>&& callback) override
      {
	socket.async_send(buf, std::move(callback));
      }

      virtual void async_receive(const asio::mutable_buffers_1& buf,
				 Function<void(const asio::error_code&, const size_t)>&& callback) override
      {
	socket.async_receive(buf, std::move(callback));
      }

      virtual std::string remote_endpoint_str() const override
      {
	return "LOCAL";
      }

      virtual bool remote_ip_port(IP::Addr&, unsigned int&) const override
      {
	return false;
      }

      virtual void non_blocking(const bool state) override
      {
	socket.non_blocking(state);
      }

      virtual bool peercreds(SockOpt::Creds& cr) override
      {
	return SockOpt::peercreds(socket.native_handle(), cr);
      }

      virtual void set_cloexec() override
      {
	SockOpt::set_cloexec(socket.native_handle());
      }

      virtual void close() override
      {
	socket.close();
      }

      virtual bool is_local() const override
      {
	return true;
      }

      asio::local::stream_protocol::socket socket;
    };
#endif
  }
}

#endif
