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
 * @brief Kernel DCO (Data Channel Offload) data plane for the server, replacing
 *  `TunReal`/`TunSink` when enabled.
 *
 * @details
 * Ports `openvpn/dco/ovpndcocli.hpp`'s (`OvpnDcoClient`) single-peer pattern to
 * the server's multi-peer case: one shared `GeNL` netlink socket and `ovpn`-
 * type netdev (vs. the client's implicit one-per-connection), one `PeerReceiver`
 * per session (vs. the client's `this`), and a `peer_id -> session` map for
 * kernel-initiated notifications (the multi-peer generalization of the
 * client's `tun_read_handler()`, which only ever checks its own one peer id).
 */

#ifndef OPENVPN_SERVER_DCOSERV_H
#define OPENVPN_SERVER_DCOSERV_H

#include <net/if.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include <openvpn/tun/tunmtu.hpp> // TUN_MTU_DEFAULT, expanded by tunnetlink.hpp below

#include <openvpn/addr/ip.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/to_string.hpp>
#include <openvpn/crypto/cryptodc.hpp>
#include <openvpn/dco/genl.hpp>
#include <openvpn/dco/korekey.hpp>
#include <openvpn/dco/ovpn_dco_linux.h>
#include <openvpn/log/logger.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/tun/linux/client/sitnl.hpp>
#include <openvpn/tun/linux/client/tunnetlink.hpp>
#include <openvpn/tun/server/tunbase.hpp>
#include <openvpn/transport/server/transbase.hpp>

namespace openvpn::DcoServ {

OPENVPN_EXCEPTION(dcoserv_error);

/**
 * @brief Device geometry for the shared `ovpn`-type netdev.
 * @details No `client_to_client` field: kernel DCO exposes no inter-peer ACL
 *  primitive, so isolation is policed externally, against this device's
 *  resolved interface name, by `openvpn::NetPolicy` (`netpolicy.hpp`).
 */
struct Config
{
    /** Requested interface name; empty lets the kernel assign one. */
    std::string dev_name;

    /** The interface's own tunnel-side address (the server's gateway). */
    IP::Addr gateway;

    /** Prefix length of the shared tunnel subnet. */
    unsigned int prefix_len = 24;

    /** Interface MTU. */
    unsigned int mtu = 1500;
};

class Channel;

/**
 * @brief Look up the session registered for a kernel peer id.
 * @details Factored out of `Channel::handle_peer_del_ntf()` as a pure
 *  function so the dispatch logic is directly unit-testable without a real
 *  netlink socket -- same split this repo already uses for
 *  `TunReal::should_forward()`.
 * @param peer_to_session The channel's peer-id-to-session map.
 * @param peer_id The id to look up.
 * @return The session, or `nullptr` if no session is registered for it.
 */
inline TransportClientInstance::Recv *find_peer_session(
    const std::map<int, TransportClientInstance::Recv *> &peer_to_session,
    const int peer_id)
{
    const auto it = peer_to_session.find(peer_id);
    return it == peer_to_session.end() ? nullptr : it->second;
}

/**
 * @brief Per-session `KoRekey::Receiver`: translates one session's rekey
 *  events into calls on the shared `Channel`.
 * @details Thin by design -- the only state is what distinguishes this
 *  session from any other (`peer_id_`), and the only logic is forwarding.
 *  Never trusts `KoRekey::Info::remote_peer_id`: that field is populated only
 *  by client-side parsing of a *server-pushed* `peer-id` option
 *  (`ProtoContext::parse_pushed_peer_id()`), so it is always `-1` on a server
 *  session. `Channel::rekey()` is given `peer_id_` directly instead.
 */
class PeerReceiver : public KoRekey::Receiver
{
  public:
    using Ptr = RCPtr<PeerReceiver>;

    /**
     * @brief Construct the receiver.
     * @param channel The shared channel this session's rekey events forward to.
     * @param peer_id This session's kernel peer id.
     * @param keepalive_ping Ping interval in seconds, armed in-kernel once the
     *  primary key installs (see `Channel::rekey()`'s `ACTIVATE_PRIMARY` case).
     * @param keepalive_timeout Timeout in seconds, same timing.
     */
    PeerReceiver(RCPtr<Channel> channel,
                 const int peer_id,
                 const unsigned int keepalive_ping,
                 const unsigned int keepalive_timeout)
        : channel_(std::move(channel)),
          peer_id_(peer_id),
          keepalive_ping_(keepalive_ping),
          keepalive_timeout_(keepalive_timeout)
    {
    }

    /**
     * @brief Forward a rekey event to the shared channel.
     * @param type Which key-lifecycle transition is occurring.
     * @param info Key material and context for the transition.
     */
    void rekey(const CryptoDCInstance::RekeyType type, const KoRekey::Info &info) override;

  private:
    RCPtr<Channel> channel_;
    int peer_id_;
    unsigned int keepalive_ping_;
    unsigned int keepalive_timeout_;
};

/**
 * @brief RAII owner of one `ovpn`-type netdev.
 *
 * @details
 * The kernel keeps an `ovpn` netdev alive until it is explicitly deleted, so
 * a server that only ever creates one leaves an `ovpnsN` behind on every run;
 * since `Channel` probes at most 256 unit names, a host accumulating them
 * eventually cannot bring DCO up at all. Owning the name in a scoped type
 * covers all three exits -- normal teardown, an exception partway through
 * `Channel`'s constructor after the netdev already exists, and a `Channel`
 * that is never explicitly stopped.
 *
 * Move-only, mirroring a file descriptor handle: exactly one owner deletes.
 */
class Netdev
{
  public:
    Netdev() = default;

    /**
     * @brief Take ownership of an existing netdev.
     * @param name Interface name to delete on destruction.
     */
    explicit Netdev(std::string name)
        : name_(std::move(name))
    {
    }

    Netdev(const Netdev &) = delete;
    Netdev &operator=(const Netdev &) = delete;

    Netdev(Netdev &&other) noexcept
        : name_(std::exchange(other.name_, std::string()))
    {
    }

    Netdev &operator=(Netdev &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            name_ = std::exchange(other.name_, std::string());
        }
        return *this;
    }

    ~Netdev()
    {
        reset();
    }

    /**
     * @brief Delete the owned netdev, if any.
     * @details Idempotent. Failures are logged rather than thrown: this runs
     *  from a destructor, and a netdev the kernel has already reclaimed is
     *  not an error worth propagating.
     */
    void reset()
    {
        if (name_.empty())
            return;
        const std::string name = std::exchange(name_, std::string());
        if (TunNetlink::SITNL::net_iface_del(name) < 0)
            OPENVPN_LOG("DCO: failed to delete iface " << name);
    }

    /**
     * @brief The owned interface name.
     * @return The name, or an empty string if this owns nothing.
     */
    const std::string &name() const
    {
        return name_;
    }

    /** @brief Whether this owns a netdev. */
    explicit operator bool() const
    {
        return !name_.empty();
    }

  private:
    std::string name_;
};

/**
 * @brief The shared kernel DCO data plane: one `ovpn`-type netdev and one
 *  `GeNL` netlink socket, serving every connected session.
 */
class Channel : public RC<thread_unsafe_refcount>
{
    friend class GeNL<Channel *>;
    friend class PeerReceiver;

  public:
    using Ptr = RCPtr<Channel>;

    /**
     * @brief Detect whether the mainline `ovpn` kernel module is loaded.
     * @details For the opportunistic-by-default check `OpenVPNServer::start()`
     *  makes before attempting to construct a `Channel` at all -- mirrors
     *  `OvpnDcoClient::available()`'s identical use of `GeNL::available()`.
     * @return True if the `ovpn` genl family resolves.
     */
    static bool available()
    {
        return GeNL<Channel *>::available();
    }

    /**
     * @brief Create and bring up the shared `ovpn`-type netdev, and bind a
     *  `GeNL` socket to it.
     * @param io_context Event loop the netlink socket attaches to.
     * @param config Device name (or empty, to let the kernel assign one),
     *  gateway address, prefix length, and MTU.
     * @throws dcoserv_error or an SITNL-logged failure if any step fails.
     * @note Linux-only, requires @c CAP_NET_ADMIN.
     */
    Channel(openvpn_io::io_context &io_context, const Config &config)
    {
        // Rejected up front rather than left to to_ipv4() below, which would
        // otherwise throw "address is not IPv4" after the netdev already exists.
        if (config.gateway.version() != IP::Addr::V4)
            throw dcoserv_error("DCO: IPv4-only data path: gateway must be an IPv4 address, got "
                                + config.gateway.to_string());

        int res = -ENOENT;
        constexpr int max_units = 256;
        for (int unit = 0; unit < max_units; ++unit)
        {
            std::string n = config.dev_name.empty() ? "ovpns" : config.dev_name;
            if (unit)
                n += openvpn::to_string(unit);
            if (n.length() >= IFNAMSIZ)
                throw dcoserv_error("DCO: ifname too long: " + n);

            // Multi-peer mode, not TunNetlink::iface_new()'s plain
            // net_iface_new(): every ovpn-type netdev defaults to
            // OVPN_MODE_P2P at creation, which new_peer() rejects outright
            // once a VPN IP is attached -- see net_iface_new_mp()'s doc
            // comment (sitnl.hpp) for how this was confirmed live.
            res = TunNetlink::SITNL::net_iface_new_mp(n);
            if (res)
            {
                OPENVPN_LOG("DCO: couldn't open iface " + n + " in multi-peer mode: " << res);
                continue;
            }
            iface_ = Netdev(std::move(n));
            break;
        }
        if (res != 0)
            throw dcoserv_error("DCO: failed to create an ovpn-type iface after trying "
                                + openvpn::to_string(max_units) + " units");

        // A mutable copy: sitnl's net_iface_mtu_set()/net_iface_up() take a
        // non-const string reference.
        std::string name = iface_.name();

        if (TunNetlink::SITNL::net_iface_mtu_set(name, config.mtu) < 0)
            throw dcoserv_error("DCO: failed to set MTU on " + name);

        const IP::Addr broadcast = config.gateway | ~IP::Addr::netmask_from_prefix_len(config.gateway.version(), config.prefix_len);
        if (TunNetlink::SITNL::net_addr_add(name, config.gateway.to_ipv4(), static_cast<unsigned char>(config.prefix_len), broadcast.to_ipv4()) < 0)
            throw dcoserv_error("DCO: failed to assign address on " + name);

        if (TunNetlink::SITNL::net_iface_up(name, true) < 0)
            throw dcoserv_error("DCO: failed to bring up " + name);

        const unsigned int ifindex = if_nametoindex(name.c_str());
        if (!ifindex)
            throw dcoserv_error("DCO: cannot resolve ifindex for " + name);
        genl_.reset(new GeNL<Channel *>(io_context, ifindex, this));
    }

    /** @brief The kernel-assigned or requested interface name. */
    const std::string &iface_name() const
    {
        return iface_.name();
    }

    /**
     * @brief Record the shared transport socket's fd, for @c add_peer() calls.
     * @details Every session shares this one fd -- the kernel demuxes by
     *  remote endpoint once a peer is registered, not by fd. Must be called
     *  after the transport socket is open (i.e. after
     *  `UDPTransportServer::Server::start()`, not at its construction).
     * @param fd The listening socket's native handle.
     */
    void set_transport_fd(const int fd)
    {
        transport_fd_ = fd;
    }

    /**
     * @brief Register one session as a kernel peer, and hand back a receiver
     *  for its data-channel factory to be wrapped with.
     * @param peer_id This session's peer id (already assigned by the
     *  transport layer before auth/address-assignment ran).
     * @param vpn_addr This session's assigned tunnel address (unlike a
     *  client's single implicit peer, a server peer needs a real VPN address
     *  so the kernel can route a tun-side packet to the right peer).
     * @param remote The client's transport-layer address, for the kernel's
     *  remote-endpoint match.
     * @param session Borrowed, not owned; used only as a lookup key for
     *  kernel-initiated notifications, released in @c del_peer().
     * @param keepalive_ping Ping interval in seconds, armed in-kernel once
     *  this session's primary key installs.
     * @param keepalive_timeout Timeout in seconds, same timing.
     * @return A `PeerReceiver` for the caller to install via
     *  `TransportClientInstance::Recv::override_dc_factory()`.
     * @throws dcoserv_error if @c set_transport_fd() was never called.
     */
    PeerReceiver::Ptr add_peer(const int peer_id,
                               const IP::Addr &vpn_addr,
                               const AddrPort &remote,
                               TransportClientInstance::Recv *session,
                               const unsigned int keepalive_ping,
                               const unsigned int keepalive_timeout)
    {
        if (transport_fd_ < 0)
            throw dcoserv_error("DCO: add_peer() called before set_transport_fd()");

        struct sockaddr_storage sa{};
        socklen_t salen = 0;
        remote_sockaddr(remote, sa, salen);

        OPENVPN_LOG("DCO: adding peer " << peer_id << " remote " << remote.to_string()
                                        << " vpn-addr " << vpn_addr);

        genl_->new_peer(peer_id,
                        transport_fd_,
                        reinterpret_cast<struct sockaddr *>(&sa),
                        salen,
                        vpn_addr.to_ipv4(),
                        IPv6::Addr());

        peer_to_session_[peer_id] = session;
        return PeerReceiver::Ptr(new PeerReceiver(Ptr(this), peer_id, keepalive_ping, keepalive_timeout));
    }

    /**
     * @brief Proactively remove a kernel peer, e.g. on session teardown.
     * @details Idempotent: a no-op if @p peer_id was never registered (a
     *  session may tear down before DCO ever engaged for it).
     * @param peer_id The peer id to remove.
     */
    void del_peer(const int peer_id)
    {
        if (peer_to_session_.erase(peer_id) == 0)
            return;
        OPENVPN_LOG("DCO: deleting peer " << peer_id);
        genl_->del_peer(peer_id);
    }

    /**
     * @brief Close the netlink socket and delete the netdev. Idempotent.
     * @details Order matters: the `GeNL` socket is bound to the netdev's
     *  ifindex, so it is closed first. The destructor does the same via
     *  member ordering, making an explicit `stop()` an optimization rather
     *  than a requirement.
     */
    void stop()
    {
        if (genl_)
            genl_->stop();
        iface_.reset();
        // Nothing may resolve a session through this map once the socket is
        // gone. In practice the transport server has already torn every
        // session down, and each del_peer() erased its own entry -- but that
        // ordering is the caller's, not this class's, so do not leave raw
        // pointers behind on the strength of it.
        peer_to_session_.clear();
    }

    /**
     * @brief `GeNL`'s `ReadHandler` contract: dispatch a kernel notification.
     * @param buf First byte is the command (or -1 for a transport-level
     *  error), remaining bytes are command-specific -- see `GeNL`'s own file
     *  doc comment for the exact layout.
     * @return Always @c true (GeNL does not itself act on this value; kept
     *  for parity with the client-side `ReadHandler` contract).
     */
    bool tun_read_handler(BufferAllocated &buf)
    {
        int8_t cmd = -1;
        buf.read(&cmd, sizeof(cmd));

        switch (cmd)
        {
        case OVPN_CMD_PEER_DEL_NTF:
            {
                uint32_t peer_id = 0;
                buf.read(&peer_id, sizeof(peer_id));
                uint8_t reason = 0;
                buf.read(&reason, sizeof(reason));
                handle_peer_del_ntf(static_cast<int>(peer_id), reason);
                break;
            }
        case -1:
            OPENVPN_LOG("DCO: netlink error: " << buf_to_string(buf));
            break;
        default:
            OPENVPN_LOG("DCO: unhandled netlink command " << static_cast<int>(cmd));
            break;
        }
        return true;
    }

  private:
    /**
     * @brief Translate one rekey event into `GeNL` calls.
     * @details Direct port of `OvpnDcoClient::rekey_impl()`'s switch. No
     *  idempotent-recreate-on-every-rekey bookkeeping is needed here (unlike
     *  the `clv-vpncore` reference implementation this was checked against):
     *  `type` already disambiguates the key slot, and the peer is created
     *  once, explicitly, in `add_peer()` -- not lazily from inside this
     *  method.
     * @param peer_id The session's peer id (from `PeerReceiver`, never from
     *  `info.remote_peer_id` -- see `PeerReceiver`'s doc comment).
     * @param type Which key-lifecycle transition is occurring.
     * @param info Key material; copied so `remote_peer_id` can be overwritten
     *  before building the kernel key config.
     * @param keepalive_ping Ping interval in seconds, armed only on
     *  `ACTIVATE_PRIMARY` (mirrors `OvpnDcoClient::rekey_impl()`).
     * @param keepalive_timeout Timeout in seconds, same timing.
     */
    void rekey(const int peer_id,
               const CryptoDCInstance::RekeyType type,
               KoRekey::Info info,
               const unsigned int keepalive_ping,
               const unsigned int keepalive_timeout)
    {
        info.remote_peer_id = peer_id;
        const KoRekey::OvpnDcoKey key(type, info);
        const auto *kc = key();

        switch (type)
        {
        case CryptoDCInstance::ACTIVATE_PRIMARY:
            OPENVPN_LOG("DCO: installing PRIMARY key for peer " << peer_id);
            genl_->new_key(OVPN_KEY_SLOT_PRIMARY, kc);
            set_peer_keepalive(peer_id, keepalive_ping, keepalive_timeout);
            break;
        case CryptoDCInstance::NEW_SECONDARY:
            OPENVPN_LOG("DCO: installing SECONDARY key for peer " << peer_id);
            genl_->new_key(OVPN_KEY_SLOT_SECONDARY, kc);
            break;
        case CryptoDCInstance::PRIMARY_SECONDARY_SWAP:
            OPENVPN_LOG("DCO: swapping keys for peer " << peer_id);
            genl_->swap_keys(peer_id);
            break;
        case CryptoDCInstance::DEACTIVATE_SECONDARY:
            OPENVPN_LOG("DCO: deleting SECONDARY key for peer " << peer_id);
            genl_->del_key(peer_id, OVPN_KEY_SLOT_SECONDARY);
            break;
        case CryptoDCInstance::DEACTIVATE_ALL:
            OPENVPN_LOG("DCO: deleting all keys for peer " << peer_id);
            genl_->del_key(peer_id, OVPN_KEY_SLOT_PRIMARY);
            genl_->del_key(peer_id, OVPN_KEY_SLOT_SECONDARY);
            break;
        default:
            OPENVPN_LOG("DCO: unhandled rekey type " << static_cast<int>(type) << " for peer " << peer_id);
            break;
        }
    }

    /**
     * @brief Arm kernel-owned keepalive for one peer.
     * @details Called once, right after a session's primary key is installed
     *  (mirroring `OvpnDcoClient::handle_keepalive()`); the caller
     *  (`HandlerMan::ManSend`) is responsible for disabling userspace
     *  keepalive via `disable_keepalive()` at the same point.
     * @param peer_id The peer to configure.
     * @param keepalive_ping Ping interval in seconds.
     * @param keepalive_timeout Timeout in seconds.
     */
    void set_peer_keepalive(const int peer_id, const unsigned int keepalive_ping, const unsigned int keepalive_timeout)
    {
        OPENVPN_LOG("DCO: setting peer " << peer_id << " keepalive interval=" << keepalive_ping
                                         << " timeout=" << keepalive_timeout);
        genl_->set_peer(peer_id, keepalive_ping, keepalive_timeout);
    }

    /**
     * @brief Handle a kernel-initiated peer deletion notification.
     * @details `OVPN_DEL_PEER_REASON_USERSPACE` means our own `del_peer()`
     *  call caused this -- the session is already tearing itself down via
     *  that same call path, so nothing further happens here beyond the
     *  bookkeeping `del_peer()` already did. Any other reason (keepalive
     *  timeout, transport error, kernel-side teardown) is unsolicited: stop
     *  the session directly, since this is the only place that ever learns
     *  about it.
     * @param peer_id The peer the kernel removed.
     * @param reason One of `OVPN_DEL_PEER_REASON_*`.
     */
    void handle_peer_del_ntf(const int peer_id, const uint8_t reason)
    {
        if (reason == OVPN_DEL_PEER_REASON_USERSPACE)
            return;

        TransportClientInstance::Recv *session = find_peer_session(peer_to_session_, peer_id);
        if (!session)
        {
            OPENVPN_LOG("DCO: peer " << peer_id << " deleted by kernel (reason " << static_cast<int>(reason)
                                     << ") but no session is tracking it");
            return;
        }

        OPENVPN_LOG("DCO: peer " << peer_id << " deleted by kernel, reason " << static_cast<int>(reason)
                                 << " -- stopping session");
        peer_to_session_.erase(peer_id);
        session->stop();
    }

    /**
     * @brief Build a `sockaddr_storage` from a client's transport address.
     * @param remote The address/port to encode.
     * @param[out] sa The encoded address.
     * @param[out] salen The length of the encoded address.
     */
    static void remote_sockaddr(const AddrPort &remote, struct sockaddr_storage &sa, socklen_t &salen)
    {
        std::memset(&sa, 0, sizeof(sa));
        if (remote.addr.version() == IP::Addr::V4)
        {
            salen = sizeof(struct sockaddr_in);
            *reinterpret_cast<struct sockaddr_in *>(&sa) = remote.addr.to_ipv4().to_sockaddr(remote.port);
        }
        else
        {
            salen = sizeof(struct sockaddr_in6);
            *reinterpret_cast<struct sockaddr_in6 *>(&sa) = remote.addr.to_ipv6().to_sockaddr(remote.port);
        }
    }

    // Declared before genl_ so that reverse-order destruction closes the
    // netlink socket bound to this netdev before deleting the netdev itself.
    Netdev iface_;
    GeNL<Channel *>::Ptr genl_;
    int transport_fd_ = -1;
    std::map<int, TransportClientInstance::Recv *> peer_to_session_;
};

inline void PeerReceiver::rekey(const CryptoDCInstance::RekeyType type, const KoRekey::Info &info)
{
    channel_->rekey(peer_id_, type, info, keepalive_ping_, keepalive_timeout_);
}

} // namespace openvpn::DcoServ

#endif
