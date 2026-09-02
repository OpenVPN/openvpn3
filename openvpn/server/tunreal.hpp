//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2026- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

/**
 * @file
 * @brief A real Linux TUN device data plane for the classic (non-DCO) server
 *  path, replacing @c TunSink (`tunsink.hpp`) with one that actually carries
 *  payload.
 *
 * @details
 * One device, and one file descriptor, is shared across every connected
 * client: a server-side tun device carries plaintext for all clients
 * simultaneously, unlike a client's 1:1 tun. The async read loop reuses
 * `openvpn::TunIO` via `TunLinux::Tun` (`tun/linux/client/tuncli.hpp`) exactly
 * as the client backend does; the only new code here is opening and
 * configuring the device, and demultiplexing an inbound packet's destination
 * address to the owning session via `PeerRoutes::RouteTable`. That table is
 * all this layer is given: the address pool it is filled from belongs to the
 * management layer, which is the only thing that allocates (peerroutes.hpp).
 *
 * Per-client `TunSend` objects are thin: `tun_send`/`tun_send_const` write
 * straight to the shared device with no demuxing needed on that side, since a
 * write is inherently addressed by the kernel's own routing, not by us.
 *
 * Client-to-client policy is enforced externally, by an nftables `FORWARD`-hook
 * rule (`openvpn/server/netpolicy.hpp`) installed against this device's
 * resolved `iface_name()`. The ingress reverse-path check below is a separate
 * concern and stays here: it defends against a client forging another
 * client's source address, a property of the authenticated data channel that
 * no netfilter rule can see.
 */

#ifndef OPENVPN_SERVER_TUNREAL_H
#define OPENVPN_SERVER_TUNREAL_H

#include <fcntl.h>
#include <cstring>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <optional>
#include <string>
#include <utility>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/alignment.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/ip/ip4.hpp>
#include <openvpn/ip/ip6.hpp>
#include <openvpn/ip/ipcommon.hpp>
#include <openvpn/log/logger.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/peerroutes.hpp>
#include <openvpn/tun/tunmtu.hpp> // TUN_MTU_DEFAULT, expanded by tunnetlink.hpp/tuncli.hpp below
#include <openvpn/tun/linux/client/sitnl.hpp>
#include <openvpn/tun/linux/client/tuncli.hpp>
#include <openvpn/tun/server/tunbase.hpp>

namespace openvpn::TunReal {

OPENVPN_EXCEPTION(tunreal_error);

/**
 * @brief Device geometry: the interface's own address and the pool it serves.
 */
struct Config
{
    /** Requested interface name; empty lets the kernel assign one (e.g. tun0). */
    std::string dev_name;

    /** The interface's own tunnel-side address (the server's gateway). */
    IP::Addr gateway;

    /** Prefix length of the shared tunnel subnet. */
    unsigned int prefix_len = 24;

    /** Interface MTU. */
    unsigned int mtu = 1500;
};

/**
 * @brief Source and destination addresses of a plaintext IP packet.
 */
struct PacketAddrs
{
    IP::Addr src;
    IP::Addr dst;
};

/**
 * @brief Parse the source and destination addresses out of a plaintext IP packet.
 * @param buf The decrypted packet as it would be written to (or was read
 *  from) the tun device. Not modified.
 * @return The packet's addresses, or @c std::nullopt if @p buf is too short
 *  for a full header of its declared version, or its version field is
 *  neither 4 nor 6.
 */
inline std::optional<PacketAddrs> extract_addrs(const Buffer &buf)
{
    if (buf.empty())
        return std::nullopt;

    switch (IPCommon::version(buf[0]))
    {
    case IPCommon::IPv4:
        {
            if (buf.size() < sizeof(IPv4Header))
                return std::nullopt;
            const auto hdr = alignment_safe_extract<IPv4Header>(buf.c_data());
            return PacketAddrs{
                .src = IP::Addr::from_ipv4(IPv4::Addr::from_uint32_net(hdr.saddr)),
                .dst = IP::Addr::from_ipv4(IPv4::Addr::from_uint32_net(hdr.daddr))};
        }

    case IPCommon::IPv6:
        {
            if (buf.size() < sizeof(IPv6Header))
                return std::nullopt;
            const auto hdr = alignment_safe_extract<IPv6Header>(buf.c_data());
            return PacketAddrs{
                .src = IP::Addr::from_ipv6(IPv6::Addr::from_in6_addr(&hdr.saddr)),
                .dst = IP::Addr::from_ipv6(IPv6::Addr::from_in6_addr(&hdr.daddr))};
        }

    default:
        return std::nullopt;
    }
}

/**
 * @brief Parse the destination address out of a plaintext IP packet.
 * @param buf The decrypted packet as it would be written to (or was read
 *  from) the tun device. Not modified.
 * @return The packet's destination address, or @c std::nullopt if @p buf is
 *  too short for a full header of its declared version, or its version field
 *  is neither 4 nor 6.
 */
inline std::optional<IP::Addr> extract_dest_addr(const Buffer &buf)
{
    const auto addrs = extract_addrs(buf);
    return addrs ? std::make_optional(addrs->dst) : std::nullopt;
}

/**
 * @brief Decide whether a packet arriving from a client may be written to the
 *  tun device, given the address that client was assigned.
 * @details The ingress counterpart to the client-to-client policy now enforced
 *  in netfilter (`server/netpolicy.hpp`), and the check that makes that policy
 *  mean anything: nothing in the protocol stops a client putting an arbitrary
 *  source address in its own authenticated data channel, and a source outside
 *  the pool does not match the intra-pool drop rule at all. Without this, a
 *  client reaches any other client by sourcing from an address outside the
 *  pool, and can impersonate arbitrary hosts to anything routable behind the
 *  server.
 *
 *  Matches OpenVPN 2's own behaviour, which drops a packet whose source is not
 *  an address learned for that client.
 * @param src The packet's source address, as the client wrote it.
 * @param assigned The tunnel address this session was actually assigned.
 * @return True if the packet may proceed to the device.
 */
inline bool source_is_permitted(const IP::Addr &src, const IP::Addr &assigned)
{
    return src == assigned;
}

/**
 * @brief Open, configure, and bring up a Linux TUN device.
 * @param config Requested name, address, prefix length, and MTU.
 * @return The open, non-blocking file descriptor and the kernel-assigned
 *  interface name (which may differ from @c config.dev_name if it was empty
 *  or already in use).
 * @throws tunreal_error or an SITNL-logged failure (returned as a thrown
 *  tunreal_error) if any step fails.
 * @note Linux-only, requires @c CAP_NET_ADMIN. Matches RFC N3: the server's
 *  syscall layer ships Linux first.
 */
inline std::pair<ScopedFD, std::string> open_and_configure(const Config &config)
{
    ScopedFD fd(open("/dev/net/tun", O_RDWR));
    if (!fd.defined())
        throw tunreal_error("open /dev/net/tun: " + std::string(std::strerror(errno)));

    struct ifreq ifr{};
    ifr.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    if (!config.dev_name.empty())
    {
        if (config.dev_name.size() >= IFNAMSIZ)
            throw tunreal_error("tun device name too long: " + config.dev_name);
        // ifr is already zeroed, so the bounded copy stays NUL-terminated.
        std::strncpy(ifr.ifr_name, config.dev_name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(fd(), TUNSETIFF, static_cast<void *>(&ifr)) < 0)
        throw tunreal_error("TUNSETIFF " + config.dev_name + ": " + std::string(std::strerror(errno)));

    if (fcntl(fd(), F_SETFL, O_NONBLOCK) < 0)
        throw tunreal_error("fcntl O_NONBLOCK: " + std::string(std::strerror(errno)));

    std::string iface_name = ifr.ifr_name;

    if (TunNetlink::SITNL::net_iface_mtu_set(iface_name, config.mtu) < 0)
        throw tunreal_error("failed to set MTU on " + iface_name);

    // Rejected explicitly rather than left to to_ipv4() below, which would
    // otherwise throw "address is not IPv4" from halfway through device setup.
    if (config.gateway.version() != IP::Addr::V4)
        throw tunreal_error("IPv4-only data path: gateway must be an IPv4 address, got "
                            + config.gateway.to_string());

    const IP::Addr broadcast = config.gateway | ~IP::Addr::netmask_from_prefix_len(config.gateway.version(), config.prefix_len);
    if (TunNetlink::SITNL::net_addr_add(iface_name, config.gateway.to_ipv4(), static_cast<unsigned char>(config.prefix_len), broadcast.to_ipv4()) < 0)
        throw tunreal_error("failed to assign address on " + iface_name);

    if (TunNetlink::SITNL::net_iface_up(iface_name, true) < 0)
        throw tunreal_error("failed to bring up " + iface_name);

    return {std::move(fd), iface_name};
}

class Device;

/**
 * @brief Per-client tun-layer object. Writes go straight to the shared device.
 */
class TunSend : public TunClientInstance::Send
{
  public:
    using Ptr = RCPtr<TunSend>;

    /**
     * @brief Construct the per-client tun object.
     * @param device The shared device. Retained so writes reach it.
     * @param assigned The tunnel address this session was assigned. Every
     *  packet this session sends must be sourced from it; see
     *  @c source_is_permitted().
     */
    TunSend(RCPtr<Device> device, const IP::Addr &assigned);

    /**
     * @brief Drop the device reference.
     * @details Does not release the client's pool address: the management
     *  instance owns both halves of that pair (see peerroutes.hpp).
     */
    void stop() override;

    /** @copydoc TunClientInstance::Send::tun_send_const */
    bool tun_send_const(const Buffer &buf) override;

    /** @copydoc TunClientInstance::Send::tun_send */
    bool tun_send(BufferAllocated &buf) override
    {
        return tun_send_const(buf);
    }

    /** @brief No native handle is exposed; the device owns the real fd. */
    TunClientInstance::NativeHandle tun_native_handle() override
    {
        return TunClientInstance::NativeHandle();
    }

    /** @brief Relay setup, which this backend does not support. */
    void relay(const IP::Addr & /* target */, const int /* port */) override
    {
    }

    /** @copydoc TunClientInstance::Send::tun_info */
    const std::string &tun_info() const override;

  private:
    RCPtr<Device> device_;
    IP::Addr assigned_;
};

/**
 * @brief Owns the tun fd, the async read loop, and the address→session map.
 *
 * @details
 * Implements `TunLinux::Tun`'s `ReadHandler` contract (`tun_read_handler`,
 * `tun_error_handler`) to receive packets from the kernel, and forwards them
 * to whichever session's address matches the packet's destination.
 */
class Device : public RC<thread_unsafe_refcount>
{
    friend class TunIO<Device *, TunLinux::PacketFrom, openvpn_io::posix::stream_descriptor>;

  public:
    using Ptr = RCPtr<Device>;

    /**
     * @brief Open and configure the device, but do not yet start reading.
     * @param io_context Event loop the device's stream attaches to.
     * @param config Requested name, address, prefix length, and MTU.
     * @param frame Buffer geometry.
     * @param stats Server-wide statistics sink.
     * @param routes Shared route table, used only to resolve a packet's
     *  destination to its session. Borrowed; must outlive this device.
     * @throws tunreal_error (see @c open_and_configure).
     */
    Device(openvpn_io::io_context &io_context,
           const Config &config,
           const Frame::Ptr &frame,
           const SessionStats::Ptr &stats,
           PeerRoutes::RouteTable *routes)
        : routes_(routes)
    {
        auto [fd, iface_name] = open_and_configure(config);
        iface_name_ = iface_name;
        // fd stays owned here. TunLinux::Tun sets TunIO::retain_stream, so
        // TunIO::stop() detaches the descriptor (stream->release()) instead of
        // closing it, and ~TunIO only deletes the stream object -- the client
        // relies on TunPersist's ScopedFD to be the real owner. Without a
        // second owner on this side the descriptor leaks and the tun device
        // stays up for the life of the process.
        tun_.reset(new TunImpl(io_context, this, frame, stats, fd(), iface_name));
        fd_ = std::move(fd);
    }

    /**
     * @brief Begin the async read loop.
     * @param n_parallel Number of outstanding reads to keep posted.
     */
    void start(const int n_parallel = 4)
    {
        tun_->start(n_parallel);
    }

    /**
     * @brief Stop the read loop and close the device.
     * @details Idempotent. Closes the descriptor after detaching it from asio,
     *  which is what actually removes the interface.
     */
    void stop()
    {
        tun_->stop();
        fd_.close();
    }

    /**
     * @brief Write a decrypted packet to the tun device.
     * @param buf The plaintext packet.
     * @return True if the write succeeded in full.
     */
    bool write(Buffer &buf)
    {
        return tun_->write(buf);
    }

    /**
     * @brief Write a packet to the device without modifying or copying it.
     * @param buf The packet to write. Not modified.
     * @return True if the whole packet was written.
     */
    bool write_const(const Buffer &buf)
    {
        return tun_->write_const(buf);
    }

    /**
     * @brief The address the route table holds for a session.
     * @param session The session to look up.
     * @return Its assigned address, or @c std::nullopt if it has none.
     */
    std::optional<IP::Addr> assigned_addr(const TunClientInstance::Recv *session) const
    {
        return routes_->addr_for(session);
    }

    /** @brief The kernel-assigned or requested interface name. */
    const std::string &iface_name() const
    {
        return iface_name_;
    }

  private:
    using TunImpl = TunLinux::Tun<Device *>;

    /**
     * @brief Deliver one packet read from the tun device to its owning session.
     * @param pfp The packet, in an @c SPtr the read loop reuses afterward.
     */
    void tun_read_handler(TunLinux::PacketFrom::SPtr &pfp)
    {
        const std::optional<IP::Addr> dest_addr = extract_dest_addr(pfp->buf);
        if (!dest_addr)
            return;

        // No route for this destination: silently drop, matching how an
        // ordinary IP stack drops to an unreachable destination.
        if (TunClientInstance::Recv *dest_session = routes_->lookup(*dest_addr))
            dest_session->tun_recv(pfp->buf);
    }

    /**
     * @brief Handle a tun device I/O error.
     * @param errtype The error category.
     * @param error The underlying system error, if any.
     */
    void tun_error_handler(const Error::Type errtype, const openvpn_io::error_code *error)
    {
        OPENVPN_LOG("TunReal::Device: error " << Error::name(errtype)
                                              << (error ? (": " + error->message()) : ""));
    }

    PeerRoutes::RouteTable *routes_;
    std::string iface_name_;

    // Declared before tun_ so reverse-order destruction detaches the stream
    // (~TunIO) before this closes the descriptor it was built over.
    ScopedFD fd_;
    TunImpl::Ptr tun_;
};

/**
 * @brief TunFactory producing one @c TunSend per connected client, all sharing
 *  one @c Device.
 */
class TunFactory : public TunClientInstance::Factory
{
  public:
    using Ptr = RCPtr<TunFactory>;

    /**
     * @brief Construct the factory.
     * @param device The shared device every @c TunSend will write through.
     */
    explicit TunFactory(Device::Ptr device)
        : device_(std::move(device))
    {
    }

    /**
     * @brief Create the tun-layer object for one client session.
     * @details The session's assigned address comes from the route table
     *  rather than being threaded through the tun factory's signature: the
     *  management layer has already leased it and registered it under this
     *  same session identity by the time a tun object is asked for (a tun
     *  instance is created lazily, at push time). Reading it back here keeps
     *  the seam unchanged and the pool the single source of truth.
     * @param parent The protocol session requesting a tun layer. Borrowed,
     *  not owned.
     * @return A new @c TunSend bound to the shared device.
     * @throws tunreal_error if no address is registered for @p parent, which
     *  would mean a tun object was requested for a session that never got a
     *  lease -- the reverse-path check has nothing to check against, so this
     *  fails closed rather than forwarding unchecked.
     */
    TunClientInstance::Send::Ptr new_tun_obj(TunClientInstance::Recv *parent) override
    {
        const std::optional<IP::Addr> assigned = device_->assigned_addr(parent);
        if (!assigned)
            throw tunreal_error("no pool address registered for this session");
        return TunClientInstance::Send::Ptr(new TunSend(device_, *assigned));
    }

  private:
    Device::Ptr device_;
};

inline TunSend::TunSend(RCPtr<Device> device, const IP::Addr &assigned)
    : device_(std::move(device)), assigned_(assigned)
{
}

inline void TunSend::stop()
{
    device_.reset();
}

inline bool TunSend::tun_send_const(const Buffer &buf)
{
    if (!device_)
        return false;

    // Reverse-path check on ingress. A packet we cannot parse is dropped
    // rather than passed: the device would receive bytes no policy has been
    // applied to.
    const std::optional<PacketAddrs> addrs = extract_addrs(buf);
    if (!addrs || !source_is_permitted(addrs->src, assigned_))
        return false;

    return device_->write_const(buf);
}

inline const std::string &TunSend::tun_info() const
{
    static const std::string info = "REAL_TUN";
    return info;
}

} // namespace openvpn::TunReal

#endif
