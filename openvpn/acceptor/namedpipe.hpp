//
//  namedpipe.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_ACCEPTOR_NAMEDPIPE_H
#define OPENVPN_ACCEPTOR_NAMEDPIPE_H

#include <openvpn/acceptor/base.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/secattr.hpp>

namespace openvpn {
  namespace Acceptor {

    class NamedPipe : public Base
    {
    public:
      OPENVPN_EXCEPTION(named_pipe_acceptor_error);

      typedef RCPtr<NamedPipe> Ptr;

      NamedPipe(asio::io_context& io_context,
		const std::string& name_arg,
		const std::string& sddl_string)
	: name(name_arg),
	  handle(io_context),
	  sa(sddl_string, false, "named pipe")
      {
      }

      virtual void async_accept(ListenerBase* listener,
				const size_t acceptor_index,
				asio::io_context& io_context) override
      {
	// create the named pipe
	const HANDLE h = ::CreateNamedPipeA(
	    name.c_str(),
	    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
#if _WIN32_WINNT >= 0x0600 // Vista and higher
	    PIPE_REJECT_REMOTE_CLIENTS |
#endif
	    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
	    PIPE_UNLIMITED_INSTANCES,
	    2048, // output buffer size
	    2048, // input buffer size
	    0,
	    &sa.sa);
	if (!Win::Handle::defined(h))
	  {
	    const asio::error_code err(::GetLastError(), asio::error::get_system_category());
	    OPENVPN_THROW(named_pipe_acceptor_error, "failed to create named pipe: " << name << " : " << err.message());
	  }

	// wait for connection (asynchronously)
	{
	  handle.assign(h);
	  asio::windows::overlapped_ptr over(
	      io_context,
	      [self=Ptr(this), listener=ListenerBase::Ptr(listener), acceptor_index]
	      (const asio::error_code& ec, size_t bytes_transferred) {
		// accept client connection
		listener->handle_accept(new AsioPolySock::NamedPipe(std::move(self->handle), acceptor_index),
					ec.value() == ERROR_PIPE_CONNECTED // not an error
					  ? asio::error_code()
					  : ec);
	      });

	  const BOOL ok = ::ConnectNamedPipe(handle.native_handle(), over.get());
	  const DWORD err = ::GetLastError();
	  if (!ok && err != ERROR_IO_PENDING)
	    {
	      // The operation completed immediately,
	      // so a completion notification needs
	      // to be posted. When complete() is called,
	      // ownership of the OVERLAPPED-derived
	      // object passes to the io_service.
	      const asio::error_code ec(err, asio::error::get_system_category());
	      over.complete(ec, 0);
	    }
	  else // ok || err == ERROR_IO_PENDING
	    {
	      // The operation was successfully initiated,
	      // so ownership of the OVERLAPPED-derived object
	      // has passed to the io_service.
	      over.release();
	    }
	}
      }

      virtual void close() override
      {
	handle.close();
      }

    private:
      std::string name;
      asio::windows::stream_handle handle;
      Win::SecurityAttributes sa;
    };

  }
}

#endif
