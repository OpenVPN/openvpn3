//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#pragma once

#include <openvpn/acceptor/base.hpp>
#include <openvpn/ssl/sslconsts.hpp>

namespace openvpn::Acceptor {

struct TCP : public Base
{
    typedef RCPtr<TCP> Ptr;

    TCP(openvpn_io::io_context &io_context)
        : acceptor(io_context)
    {
    }

    void async_accept(ListenerBase *listener,
                      const size_t acceptor_index,
                      openvpn_io::io_context &io_context) override
    {
        AsioPolySock::TCP::Ptr sock(new AsioPolySock::TCP(io_context, acceptor_index));
        acceptor.async_accept(sock->socket,
                              [listener = ListenerBase::Ptr(listener), sock](const openvpn_io::error_code &error) mutable
                              { listener->handle_accept(std::move(sock), error); });
    }

    void close() override
    {
#ifdef OPENVPN_DEBUG_ACCEPT
        OPENVPN_LOG("ACCEPTOR CLOSE " << local_endpoint);
#endif
        acceptor.close();
    }

    enum
    {
        // start at (1<<24) to avoid conflicting with SSLConst flags
        DISABLE_REUSE_ADDR = (1 << 24),
        REUSE_PORT = (1 << 25),

        FIRST = DISABLE_REUSE_ADDR
    };
    void set_socket_options(unsigned int flags)
    {
        static_assert(int(FIRST) > int(SSLConst::LAST), "TCP flags in conflict with SSL flags");

#if defined(OPENVPN_PLATFORM_WIN)
        // set Windows socket flags
        if (!(flags & DISABLE_REUSE_ADDR))
            acceptor.set_option(openvpn_io::ip::tcp::acceptor::reuse_address(true));
#else
        // set Unix socket flags
        {
            const int fd = acceptor.native_handle();
            if (flags & REUSE_PORT)
                SockOpt::reuseport(fd);
            if (!(flags & DISABLE_REUSE_ADDR))
                SockOpt::reuseaddr(fd);
            SockOpt::set_cloexec(fd);
        }
#endif
    }

    // filter all but socket option flags
    static unsigned int sockopt_flags(const unsigned int flags)
    {
        return flags & (DISABLE_REUSE_ADDR | REUSE_PORT);
    }

    openvpn_io::ip::tcp::endpoint local_endpoint;
    openvpn_io::ip::tcp::acceptor acceptor;
};

} // namespace openvpn::Acceptor
