//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception

// Base class for generic link objects.

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/io/io.hpp>

#ifdef OPENVPN_GREMLIN
#include <openvpn/transport/gremlin.hpp>
#endif

#pragma once

namespace openvpn::TCPTransport {
struct PacketFrom
{
    using SPtr = std::unique_ptr<PacketFrom>;
    BufferAllocated buf;
};

class LinkBase : public RC<thread_unsafe_refcount>
{
  protected:
    virtual void recv_buffer(PacketFrom::SPtr &pfp,
                             const size_t bytes_recvd) = 0;
    virtual void from_app_send_buffer(BufferPtr &buf) = 0;

  public:
    using Ptr = RCPtr<LinkBase>;

    virtual bool send_queue_empty() const = 0;
    virtual size_t send_queue_size() const = 0;
    virtual void reset_align_adjust(const size_t align_adjust) = 0;
    virtual bool send(BufferAllocated &b) = 0;
    virtual void set_raw_mode(const bool mode) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
#ifdef OPENVPN_GREMLIN
    virtual void gremlin_config(openvpn_io::io_context &io_context,
                                const Gremlin::Config::Ptr &config) = 0;
#endif
};
} // namespace openvpn::TCPTransport
