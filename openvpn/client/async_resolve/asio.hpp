//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2019 OpenVPN Inc.
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

#ifndef OPENVPN_CLIENT_ASYNC_RESOLVE_ASIO_H
#define OPENVPN_CLIENT_ASYNC_RESOLVE_ASIO_H

#include <openvpn/io/io.hpp>
#include <openvpn/asio/asiowork.hpp>

#include <openvpn/common/bigmutex.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/hostport.hpp>


namespace openvpn {
  template<typename RESOLVER_TYPE>
  class AsyncResolvable: public virtual RC<thread_unsafe_refcount>
  {
  private:
    typedef RCPtr<AsyncResolvable> Ptr;

    openvpn_io::io_context& io_context;
    std::unique_ptr<AsioWork> asio_work;

  public:
    AsyncResolvable(openvpn_io::io_context& io_context_arg)
      : io_context(io_context_arg)
    {
    }

    virtual void resolve_callback(const openvpn_io::error_code& error,
				  typename RESOLVER_TYPE::results_type results) = 0;

    // mimic the asynchronous DNS resolution by performing a
    // synchronous one in a detached thread.
    //
    // This strategy has the advantage of allowing the core to
    // stop/exit without waiting for the getaddrinfo() (used
    // internally) to terminate.
    // Note: getaddrinfo() is non-interruptible by design.
    //
    // In other words, we are re-creating exactly what ASIO would
    // normally do in case of async_resolve(), with the difference
    // that here we have control over the resolving thread and we
    // can easily detach it. Deatching the internal thread created
    // by ASIO would not be feasible as it is not exposed.
    void async_resolve_name(const std::string& host, const std::string& port)
    {
      std::thread resolve_thread([self=Ptr(this), host, port]() {
        openvpn_io::io_context io_context(1);
	openvpn_io::error_code error;
	RESOLVER_TYPE resolver(io_context);
	typename RESOLVER_TYPE::results_type results;
	results = resolver.resolve(host, port, error);

	openvpn_io::post(self->io_context, [self, results, error]() {
	  OPENVPN_ASYNC_HANDLER;
	  self->resolve_callback(error, results);
	});
      });

      // detach the thread so that the client won't need to wait for
      // it to join.
      resolve_thread.detach();
    }

    // there might be nothing else in the main io_context queue
    // right now, therefore we use AsioWork to prevent the loop
    // from exiting while we perform the DNS resolution in the
    // detached thread.
    void async_resolve_lock()
    {
      asio_work.reset(new AsioWork(io_context));
    }

    // to be called by the child class when the core wants to stop
    // and we don't need to wait for the detached thread any longer.
    // It simulates a resolve abort
    void async_resolve_cancel()
    {
      asio_work.reset();
    }
  };
}

#endif /* OPENVPN_CLIENT_ASYNC_RESOLVE_ASIO_H */
