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
 * @brief Client-to-client isolation and IP forwarding, backend-agnostic
 *  between @c TunReal and @c DcoServ.
 *
 * @details
 * Both backends forward a client-to-client packet the same underlying way: a
 * decrypted packet is handed to the host's own routing table, which
 * re-injects it into the same device (a TUN write on the classic path, a
 * kernel-internal route on DCO -- neither `ovpn-dco` nor its genl API expose
 * an inter-peer ACL primitive). A netfilter rule on the standard `FORWARD`
 * hook, scoped to one device, therefore polices both with no backend-specific
 * code. nft rule construction rebuilt from
 * `github.com/cvigue/clv-vpncore`'s `NfTablesClient::EnsureIntraPoolDrop`
 * (Apache-2.0) against this repo's own `IP::Addr`/`OPENVPN_LOG`/exception
 * conventions.
 *
 * @c Policy is owned by the server object and keyed by device name rather
 * than assuming a single device, so a server attaching more than one
 * data-plane device needs no change here.
 */

#ifndef OPENVPN_SERVER_NETPOLICY_H
#define OPENVPN_SERVER_NETPOLICY_H

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <net/if.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <openvpn/addr/ip.hpp>
#include <openvpn/common/alignment.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/ip/ip4.hpp>
#include <openvpn/log/logger.hpp>

namespace openvpn::NetPolicy {

OPENVPN_EXCEPTION(netpolicy_error);

/**
 * @brief What one data-plane device needs policed.
 */
struct Attachment
{
    /** The device's resolved interface name (`TunReal::Device::iface_name()`
     *  or `DcoServ::Channel::iface_name()`). */
    std::string dev_name;

    /** The device's own tunnel-side address (the server's gateway). IPv4
     *  only, matching both backends' own data-plane restriction. */
    IP::Addr gateway;

    /** Prefix length of the shared tunnel subnet this device serves. */
    unsigned int prefix_len = 24;

    /** Whether client-to-client traffic is allowed through this device.
     *  When false, @c attach() installs a kernel-enforced DROP for any
     *  packet whose source and destination both fall inside the subnet
     *  above (and neither is the gateway itself). */
    bool client_to_client = false;
};

/// @cond NETPOLICY_DETAIL
namespace detail {

inline void append_bytes(std::vector<std::uint8_t> &buf, const void *data, std::size_t len)
{
    const auto *p = static_cast<const std::uint8_t *>(data);
    buf.insert(buf.end(), p, p + len);
}

inline void pad_to_4(std::vector<std::uint8_t> &buf)
{
    while (buf.size() % 4 != 0)
        buf.push_back(0);
}

inline std::size_t begin_nlmsg(std::vector<std::uint8_t> &buf, std::uint16_t type, std::uint16_t flags, std::uint32_t seq)
{
    const std::size_t pos = buf.size();
    const struct nlmsghdr nlh{
        .nlmsg_len = static_cast<std::uint32_t>(sizeof(struct nlmsghdr)), // patched by end_nlmsg()
        .nlmsg_type = type,
        .nlmsg_flags = flags,
        .nlmsg_seq = seq,
        .nlmsg_pid = 0};
    append_bytes(buf, &nlh, sizeof(nlh));
    return pos;
}

inline void end_nlmsg(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto nlh = alignment_safe_extract<struct nlmsghdr>(buf.data() + pos);
    nlh.nlmsg_len = static_cast<std::uint32_t>(buf.size() - pos);
    alignment_safe_store(buf.data() + pos, nlh);
}

inline void append_nfgenmsg(std::vector<std::uint8_t> &buf, std::uint8_t family, std::uint16_t res_id)
{
    const struct nfgenmsg nfg{
        .nfgen_family = family,
        .version = NFNETLINK_V0,
        .res_id = htons(res_id)};
    append_bytes(buf, &nfg, sizeof(nfg));
}

inline void append_attr(std::vector<std::uint8_t> &buf, std::uint16_t type, const void *data, std::size_t len)
{
    const struct nlattr nla{
        .nla_len = static_cast<std::uint16_t>(NLA_HDRLEN + len),
        .nla_type = type};
    append_bytes(buf, &nla, sizeof(nla));
    if (data && len > 0)
        append_bytes(buf, data, len);
    pad_to_4(buf);
}

inline void append_attr_str(std::vector<std::uint8_t> &buf, std::uint16_t type, const char *str)
{
    append_attr(buf, type, str, std::strlen(str) + 1);
}

inline void append_attr_u32(std::vector<std::uint8_t> &buf, std::uint16_t type, std::uint32_t val)
{
    val = htonl(val);
    append_attr(buf, type, &val, sizeof(val));
}

inline std::size_t begin_nested(std::vector<std::uint8_t> &buf, std::uint16_t type)
{
    const std::size_t pos = buf.size();
    const struct nlattr nla{
        .nla_len = 0, // patched by end_nested()
        .nla_type = static_cast<std::uint16_t>(type | NLA_F_NESTED)};
    append_bytes(buf, &nla, sizeof(nla));
    return pos;
}

inline void end_nested(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto nla = alignment_safe_extract<struct nlattr>(buf.data() + pos);
    nla.nla_len = static_cast<std::uint16_t>(buf.size() - pos);
    alignment_safe_store(buf.data() + pos, nla);
    pad_to_4(buf);
}

constexpr std::uint16_t nft_msg_type(std::uint16_t msg)
{
    return static_cast<std::uint16_t>((NFNL_SUBSYS_NFTABLES << 8) | msg);
}

inline void append_expr_payload(std::vector<std::uint8_t> &buf, std::uint32_t dreg, std::uint32_t base, std::uint32_t offset, std::uint32_t len)
{
    const auto expr = begin_nested(buf, NFTA_LIST_ELEM);
    append_attr_str(buf, NFTA_EXPR_NAME, "payload");
    const auto data = begin_nested(buf, NFTA_EXPR_DATA);
    append_attr_u32(buf, NFTA_PAYLOAD_DREG, dreg);
    append_attr_u32(buf, NFTA_PAYLOAD_BASE, base);
    append_attr_u32(buf, NFTA_PAYLOAD_OFFSET, offset);
    append_attr_u32(buf, NFTA_PAYLOAD_LEN, len);
    end_nested(buf, data);
    end_nested(buf, expr);
}

inline void append_expr_bitwise_and(std::vector<std::uint8_t> &buf, std::uint32_t sreg, std::uint32_t dreg, const std::uint8_t *mask_bytes, std::uint32_t len)
{
    const auto expr = begin_nested(buf, NFTA_LIST_ELEM);
    append_attr_str(buf, NFTA_EXPR_NAME, "bitwise");
    const auto data = begin_nested(buf, NFTA_EXPR_DATA);
    append_attr_u32(buf, NFTA_BITWISE_SREG, sreg);
    append_attr_u32(buf, NFTA_BITWISE_DREG, dreg);
    append_attr_u32(buf, NFTA_BITWISE_LEN, len);
    {
        const auto mask = begin_nested(buf, NFTA_BITWISE_MASK);
        append_attr(buf, NFTA_DATA_VALUE, mask_bytes, len);
        end_nested(buf, mask);
    }
    {
        const std::vector<std::uint8_t> zeros(len, 0);
        const auto xor_ = begin_nested(buf, NFTA_BITWISE_XOR);
        append_attr(buf, NFTA_DATA_VALUE, zeros.data(), len);
        end_nested(buf, xor_);
    }
    end_nested(buf, data);
    end_nested(buf, expr);
}

inline void append_expr_cmp(std::vector<std::uint8_t> &buf, std::uint32_t sreg, std::uint32_t op, const void *cmp_data, std::size_t cmp_len)
{
    const auto expr = begin_nested(buf, NFTA_LIST_ELEM);
    append_attr_str(buf, NFTA_EXPR_NAME, "cmp");
    const auto data = begin_nested(buf, NFTA_EXPR_DATA);
    append_attr_u32(buf, NFTA_CMP_SREG, sreg);
    append_attr_u32(buf, NFTA_CMP_OP, op);
    {
        const auto cmp = begin_nested(buf, NFTA_CMP_DATA);
        append_attr(buf, NFTA_DATA_VALUE, cmp_data, cmp_len);
        end_nested(buf, cmp);
    }
    end_nested(buf, data);
    end_nested(buf, expr);
}

inline void append_expr_meta_iifname(std::vector<std::uint8_t> &buf, std::uint32_t dreg)
{
    const auto expr = begin_nested(buf, NFTA_LIST_ELEM);
    append_attr_str(buf, NFTA_EXPR_NAME, "meta");
    const auto data = begin_nested(buf, NFTA_EXPR_DATA);
    append_attr_u32(buf, NFTA_META_DREG, dreg);
    append_attr_u32(buf, NFTA_META_KEY, NFT_META_IIFNAME);
    end_nested(buf, data);
    end_nested(buf, expr);
}

inline void append_expr_immediate_drop(std::vector<std::uint8_t> &buf)
{
    const auto expr = begin_nested(buf, NFTA_LIST_ELEM);
    append_attr_str(buf, NFTA_EXPR_NAME, "immediate");
    const auto data = begin_nested(buf, NFTA_EXPR_DATA);
    append_attr_u32(buf, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    {
        const auto imm = begin_nested(buf, NFTA_IMMEDIATE_DATA);
        const auto verdict = begin_nested(buf, NFTA_DATA_VERDICT);
        append_attr_u32(buf, NFTA_VERDICT_CODE, static_cast<std::uint32_t>(NF_DROP));
        end_nested(buf, verdict);
        end_nested(buf, imm);
    }
    end_nested(buf, data);
    end_nested(buf, expr);
}

/**
 * @brief Render an interface name into the fixed-width, NUL-padded form that
 *  the `meta iifname` comparison expects.
 * @param ifname The interface name; anything past @c IFNAMSIZ-1 is dropped.
 * @return The padded name, zero-filled to @c IFNAMSIZ bytes.
 */
inline std::array<std::uint8_t, IFNAMSIZ> pad_ifname(const std::string &ifname)
{
    std::array<std::uint8_t, IFNAMSIZ> out{};
    std::strncpy(reinterpret_cast<char *>(out.data()), ifname.c_str(), IFNAMSIZ - 1);
    return out;
}

/**
 * @brief Check that an interface name can appear verbatim in an nft table name.
 * @details Folding the disallowed characters to `_` instead would be
 *  many-to-one: `tun-0` and `tun.0` both become `tun_0`, so two servers would
 *  compute the same table, and attach deletes the table before recreating it.
 *  The second server would silently remove the first one's isolation rules. nft
 *  accepts `-` and `.` anyway, so the fold discarded information it never
 *  needed to. Refusing the handful of names nft cannot represent keeps the
 *  mapping injective and puts the diagnostic in front of the operator.
 * @param ifname The device name to check.
 * @return @p ifname unchanged.
 * @throws netpolicy_error if the name is empty or holds a character nft rejects.
 */
inline std::string validate_for_table_name(const std::string &ifname)
{
    if (ifname.empty())
        throw netpolicy_error("device name is empty; cannot form an nft table name");
    for (const unsigned char c : ifname)
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.')
            throw netpolicy_error("device name " + ifname + ": character '"
                                  + std::string(1, static_cast<char>(c))
                                  + "' cannot appear in an nft table name");
    return ifname;
}

/**
 * @brief Incrementally builds one netlink batch targeting `NETLINK_NETFILTER`.
 * @details Direct structural port of `clv-vpncore`'s `NftBatchBuilder`
 *  (Apache-2.0), rebuilt on this repo's own attribute-encoding helpers above.
 */
class BatchBuilder
{
  public:
    explicit BatchBuilder(std::size_t reserve = 2048)
    {
        buf_.reserve(reserve);
    }

    void begin()
    {
        const auto pos = begin_nlmsg(buf_, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq_++);
        append_nfgenmsg(buf_, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        end_nlmsg(buf_, pos);
    }

    void add_table(const char *table_name)
    {
        const auto pos = begin_nlmsg(buf_, nft_msg_type(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, seq_++);
        ++acks_expected_;
        append_nfgenmsg(buf_, NFPROTO_IPV4, 0);
        append_attr_str(buf_, NFTA_TABLE_NAME, table_name);
        end_nlmsg(buf_, pos);
    }

    void add_forward_chain(const char *table_name, const char *chain_name)
    {
        const auto pos = begin_nlmsg(buf_, nft_msg_type(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, seq_++);
        ++acks_expected_;
        append_nfgenmsg(buf_, NFPROTO_IPV4, 0);
        append_attr_str(buf_, NFTA_CHAIN_TABLE, table_name);
        append_attr_str(buf_, NFTA_CHAIN_NAME, chain_name);
        append_attr_str(buf_, NFTA_CHAIN_TYPE, "filter");
        {
            const auto hook = begin_nested(buf_, NFTA_CHAIN_HOOK);
            append_attr_u32(buf_, NFTA_HOOK_HOOKNUM, NF_INET_FORWARD);
            append_attr_u32(buf_, NFTA_HOOK_PRIORITY, 0);
            end_nested(buf_, hook);
        }
        end_nlmsg(buf_, pos);
    }

    void begin_rule(const char *table_name, const char *chain_name)
    {
        rule_pos_ = begin_nlmsg(buf_, nft_msg_type(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, seq_++);
        ++acks_expected_;
        append_nfgenmsg(buf_, NFPROTO_IPV4, 0);
        append_attr_str(buf_, NFTA_RULE_TABLE, table_name);
        append_attr_str(buf_, NFTA_RULE_CHAIN, chain_name);
        exprs_pos_ = begin_nested(buf_, NFTA_RULE_EXPRESSIONS);
    }

    void end_rule()
    {
        end_nested(buf_, exprs_pos_);
        end_nlmsg(buf_, rule_pos_);
    }

    void del_table(const char *table_name)
    {
        const auto pos = begin_nlmsg(buf_, nft_msg_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK, seq_++);
        ++acks_expected_;
        append_nfgenmsg(buf_, NFPROTO_IPV4, 0);
        append_attr_str(buf_, NFTA_TABLE_NAME, table_name);
        end_nlmsg(buf_, pos);
    }

    void end()
    {
        const auto pos = begin_nlmsg(buf_, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq_++);
        append_nfgenmsg(buf_, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        end_nlmsg(buf_, pos);
    }

    std::vector<std::uint8_t> &buffer()
    {
        return buf_;
    }

    const std::vector<std::uint8_t> &buffer() const
    {
        return buf_;
    }

    /** @brief Number of kernel acks a successful commit will produce. */
    std::size_t acks_expected() const
    {
        return acks_expected_;
    }

  private:
    std::vector<std::uint8_t> buf_;
    std::uint32_t seq_ = 0;
    std::size_t rule_pos_ = 0;
    std::size_t exprs_pos_ = 0;
    std::size_t acks_expected_ = 0;
};

/**
 * @brief Send one batch over a `NETLINK_NETFILTER` socket and wait for the
 *  kernel's per-command acks.
 * @details Every command message carries `NLM_F_ACK`, so a successful commit
 *  is positively confirmed by one `nlmsgerr{error=0}` per command; any
 *  nonzero error, a receive timeout, or a socket error is a failure. Fails
 *  closed: silence is never read as success.
 * @param fd The bound netlink socket.
 * @param batch The built batch, which knows how many acks to expect.
 * @return True if every command was acked.
 */
inline bool send_batch(int fd, const BatchBuilder &batch)
{
    const struct timeval timeout{.tv_sec = 0, .tv_usec = 500000};
    // Without this timeout the ack loop below can block indefinitely, which
    // would defeat the fail-closed contract documented above.
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        return false;

    if (send(fd, batch.buffer().data(), batch.buffer().size(), 0) < 0)
        return false;

    std::size_t acks = 0;
    std::vector<std::uint8_t> response(8192);
    while (acks < batch.acks_expected())
    {
        const ssize_t recv_len = recv(fd, response.data(), response.size(), 0);
        if (recv_len < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        // Open-coded NLMSG_OK/NLMSG_NEXT: the macros compare signed against
        // __u32 (rejected under -Wsign-compare) and can walk past an
        // unaligned final message.
        auto remaining = static_cast<std::size_t>(recv_len);
        auto *msg = response.data();
        while (remaining >= sizeof(struct nlmsghdr))
        {
            auto *nlh = reinterpret_cast<struct nlmsghdr *>(msg);
            if (nlh->nlmsg_len < sizeof(struct nlmsghdr) || nlh->nlmsg_len > remaining)
                break;
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                const auto *err = static_cast<const struct nlmsgerr *>(NLMSG_DATA(nlh));
                if (err->error != 0)
                    return false;
                ++acks;
            }
            const std::size_t advance = NLMSG_ALIGN(nlh->nlmsg_len);
            if (advance >= remaining)
                break;
            msg += advance;
            remaining -= advance;
        }
    }
    return true;
}

/** @brief Open a bound `NETLINK_NETFILTER` socket. */
inline ScopedFD open_netfilter_socket()
{
    ScopedFD fd(socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER));
    if (!fd.defined())
        return fd;

    struct sockaddr_nl addr{.nl_family = AF_NETLINK};
    if (bind(fd(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        fd.close();
        return fd;
    }
    return fd;
}

/**
 * @brief Install (idempotently) an nft `FORWARD`-hook DROP rule for traffic
 *  where both source and destination fall inside @p gateway / @p prefix_len,
 *  excluding @p gateway itself, on @p dev_name only.
 * @throws netpolicy_error on any failure -- isolation is a security
 *  guarantee, so a failed install must fail the attachment closed rather
 *  than silently proceed unprotected.
 */
inline void install_intra_pool_drop(const std::string &dev_name, const IP::Addr &gateway, const unsigned int prefix_len)
{
    if (dev_name.empty())
        throw netpolicy_error("install_intra_pool_drop: device name is required");
    if (gateway.version() != IP::Addr::V4)
        throw netpolicy_error("install_intra_pool_drop: IPv4-only, got " + gateway.to_string());

    const std::string table_name = "o3_c2c_" + validate_for_table_name(dev_name);

    ScopedFD fd(open_netfilter_socket());
    if (!fd.defined())
        throw netpolicy_error("install_intra_pool_drop: could not open a NETLINK_NETFILTER socket (CAP_NET_ADMIN required)");

    const IP::Addr network = gateway.network_addr(prefix_len);
    const std::uint32_t network_be = network.to_uint32_net();
    const std::uint32_t gateway_be = gateway.to_uint32_net();
    const std::uint32_t mask_be = IP::Addr::netmask_from_prefix_len(IP::Addr::V4, prefix_len).to_uint32_net();

    const std::array<std::uint8_t, IFNAMSIZ> ifname_padded = pad_ifname(dev_name);

    // Idempotent: clear out anything a previous, uncleanly-stopped run left
    // behind under this device's table name before installing fresh.
    {
        BatchBuilder clear;
        clear.begin();
        clear.del_table(table_name.c_str());
        clear.end();
        send_batch(fd(), clear); // failure expected when no stale table exists
    }

    BatchBuilder batch(4096);
    batch.begin();
    batch.add_table(table_name.c_str());
    batch.add_forward_chain(table_name.c_str(), "forward");
    batch.begin_rule(table_name.c_str(), "forward");
    {
        auto &buf = batch.buffer();
        append_expr_meta_iifname(buf, NFT_REG_1);
        append_expr_cmp(buf, NFT_REG_1, NFT_CMP_EQ, ifname_padded.data(), IFNAMSIZ);

        append_expr_payload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, offsetof(IPv4Header, saddr), 4);
        append_expr_bitwise_and(buf, NFT_REG_1, NFT_REG_1, reinterpret_cast<const std::uint8_t *>(&mask_be), sizeof(mask_be));
        append_expr_cmp(buf, NFT_REG_1, NFT_CMP_EQ, &network_be, sizeof(network_be));

        append_expr_payload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, offsetof(IPv4Header, daddr), 4);
        append_expr_bitwise_and(buf, NFT_REG_1, NFT_REG_1, reinterpret_cast<const std::uint8_t *>(&mask_be), sizeof(mask_be));
        append_expr_cmp(buf, NFT_REG_1, NFT_CMP_EQ, &network_be, sizeof(network_be));

        append_expr_payload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, offsetof(IPv4Header, daddr), 4);
        append_expr_cmp(buf, NFT_REG_1, NFT_CMP_NEQ, &gateway_be, sizeof(gateway_be));

        append_expr_payload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, offsetof(IPv4Header, saddr), 4);
        append_expr_cmp(buf, NFT_REG_1, NFT_CMP_NEQ, &gateway_be, sizeof(gateway_be));

        append_expr_immediate_drop(buf);
    }
    batch.end_rule();
    batch.end();

    if (!send_batch(fd(), batch))
        throw netpolicy_error("install_intra_pool_drop: nftables transaction failed for " + dev_name);
}

/** @brief Remove the table @c install_intra_pool_drop() created for @p dev_name, if any. */
inline void remove_intra_pool_drop(const std::string &dev_name) noexcept
{
    try
    {
        const std::string table_name = "o3_c2c_" + validate_for_table_name(dev_name);
        const ScopedFD fd(open_netfilter_socket());
        if (!fd.defined())
        {
            OPENVPN_LOG("NetPolicy: could not open NETLINK_NETFILTER socket to remove " << table_name);
            return;
        }
        BatchBuilder batch;
        batch.begin();
        batch.del_table(table_name.c_str());
        batch.end();
        if (!send_batch(fd(), batch))
            OPENVPN_LOG("NetPolicy: failed to remove nft table " << table_name);
    }
    catch (...)
    {
        // Must not throw: called from RAII teardown.
    }
}

} // namespace detail
/// @endcond

/**
 * @brief RAII per-device IPv4 forwarding toggle: enables
 *  `net.ipv4.conf.<dev>.forwarding` if it was off, and restores it on
 *  destruction. A no-op (does not "own" the setting) if it was already on.
 * @details Deliberately per-device, never the global `ip_forward`: the
 *  forwarding decision is gated on the *input* interface's flag, so the
 *  server's own device covers client-originated traffic (including the
 *  client-to-client hairpin) without changing the routing posture of any
 *  other interface -- and without a shutdown restore that could yank
 *  forwarding out from under another process. Forwarding *into* the tunnel
 *  from other interfaces remains the operator's routing policy.
 */
class ForwardingGuard
{
  public:
    /**
     * @brief Enable forwarding on @p dev_name if it is not already on.
     * @param dev_name An existing network device's name.
     * @throws netpolicy_error if the device's forwarding sysctl cannot be
     *  read or written (requires root / `CAP_NET_ADMIN`, and the device must
     *  exist).
     */
    explicit ForwardingGuard(const std::string &dev_name)
        : path_("/proc/sys/net/ipv4/conf/" + dev_name + "/forwarding")
    {
        std::ifstream in(path_);
        if (!in.is_open())
            throw netpolicy_error("cannot read " + path_ + " (root required, and the device must exist)");
        int value = 0;
        in >> value;
        if (value != 0)
            return; // already enabled; not ours to restore

        std::ofstream out(path_);
        if (!out.is_open() || !(out << "1") || !out.flush())
            throw netpolicy_error("cannot enable " + path_);
        owns_ = true;
        OPENVPN_LOG("NetPolicy: enabled IPv4 forwarding on " << dev_name);
    }

    ForwardingGuard(const ForwardingGuard &) = delete;
    ForwardingGuard &operator=(const ForwardingGuard &) = delete;
    ForwardingGuard(ForwardingGuard &&other) noexcept
        : path_(std::move(other.path_)),
          owns_(std::exchange(other.owns_, false))
    {
    }
    ForwardingGuard &operator=(ForwardingGuard &&) = delete;

    /**
     * @brief Restore forwarding to disabled, if this instance enabled it.
     * @details A device that has already been deleted takes its sysctl with
     *  it; the failed open is not an error.
     */
    ~ForwardingGuard()
    {
        if (!owns_)
            return;
        std::ofstream out(path_);
        if (out.is_open())
            out << "0";
    }

  private:
    std::string path_;
    bool owns_ = false;
};

/**
 * @brief RAII owner of one device's client-to-client isolation rule.
 * @details A no-op guard (installs nothing) when @c Attachment::client_to_client
 *  is true -- forwarding between clients is then exactly what upstream
 *  DCO and the classic path both already do unassisted.
 */
class IsolationGuard
{
  public:
    /**
     * @brief Install the isolation rule for @p att, unless it allows c2c.
     * @throws netpolicy_error if installation fails while isolation is
     *  required -- see @c detail::install_intra_pool_drop().
     */
    explicit IsolationGuard(const Attachment &att)
        : dev_name_(att.client_to_client ? std::string() : att.dev_name)
    {
        if (!dev_name_.empty())
            detail::install_intra_pool_drop(att.dev_name, att.gateway, att.prefix_len);
    }

    IsolationGuard(const IsolationGuard &) = delete;
    IsolationGuard &operator=(const IsolationGuard &) = delete;
    IsolationGuard(IsolationGuard &&other) noexcept
        : dev_name_(std::exchange(other.dev_name_, std::string()))
    {
    }
    IsolationGuard &operator=(IsolationGuard &&) = delete;

    ~IsolationGuard()
    {
        if (!dev_name_.empty())
            detail::remove_intra_pool_drop(dev_name_);
    }

  private:
    std::string dev_name_;
};

/**
 * @brief The server's single point of record for network forwarding:
 *  per-device IPv4 forwarding and client-to-client isolation.
 *
 * @details
 * Meant to be owned once by the server object, and to have @c attach() called
 * once per data-plane device that comes up (one today; nothing here assumes
 * that stays true). Not thread-safe, matching this repo's server-side
 * convention of a single-threaded control @c io_context -- callers must only
 * touch a given instance from that thread.
 */
class Policy
{
  public:
    Policy() = default;
    ~Policy()
    {
        shutdown();
    }

    Policy(const Policy &) = delete;
    Policy &operator=(const Policy &) = delete;
    Policy(Policy &&) = delete;
    Policy &operator=(Policy &&) = delete;

    /**
     * @brief Register one device: enable forwarding on it, and install its
     *  isolation rule unless the attachment allows client-to-client.
     *  Replaces any prior registration under the same name.
     * @param att The device and the policy it should enforce.
     * @throws netpolicy_error if the device does not exist, or isolation is
     *  required and installing it fails. Everything already applied for this
     *  attachment is rolled back before the throw.
     */
    void attach(const Attachment &att)
    {
        detach(att.dev_name);
        DeviceGuards guards{.forwarding = ForwardingGuard(att.dev_name),
                            .isolation = IsolationGuard(att)};
        devices_.emplace(att.dev_name, std::move(guards));
    }

    /** @brief Unregister a device, releasing everything it owned. Idempotent. */
    void detach(const std::string &dev_name)
    {
        devices_.erase(dev_name);
    }

    /** @brief Detach every device. */
    void shutdown()
    {
        devices_.clear();
    }

    /** @brief Number of currently attached devices. */
    std::size_t attachment_count() const
    {
        return devices_.size();
    }

    /** @brief Whether a device is currently attached. */
    bool has_attachment(const std::string &dev_name) const
    {
        return devices_.contains(dev_name);
    }

  private:
    struct DeviceGuards
    {
        ForwardingGuard forwarding;
        IsolationGuard isolation;
    };

    std::map<std::string, DeviceGuards> devices_;
};

} // namespace openvpn::NetPolicy

#endif
