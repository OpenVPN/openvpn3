//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//    Copyright (C) 2020-2022 Lev Stipakov <lev@openvpn.net>
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//


#pragma once

#include <openvpn/addr/ipv4.hpp>
#include <openvpn/addr/ipv6.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/dco/key.hpp>

#include <openvpn/dco/ovpn_dco_linux.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include <memory>

/* The following enum members exist in netlink.h since linux-6.1.
 * However, some distro we support still ship an old header, thus
 * failing the OpenVPN compilation.
 *
 * For the time being we add the needed defines manually.
 * We will drop this definition once we stop supporting those old
 * distros.
 *
 * @NLMSGERR_ATTR_MISS_TYPE: type of a missing required attribute,
 *  %NLMSGERR_ATTR_MISS_NEST will not be present if the attribute was
 *  missing at the message level
 * @NLMSGERR_ATTR_MISS_NEST: offset of the nest where attribute was missing
 */
enum ovpn_nlmsgerr_attrs
{
    OVPN_NLMSGERR_ATTR_MISS_TYPE = 5,
    OVPN_NLMSGERR_ATTR_MISS_NEST = 6,
    OVPN_NLMSGERR_ATTR_MAX = 6,
};

namespace openvpn {

#define nla_nest_start(_msg, _type) nla_nest_start(_msg, (_type) | NLA_F_NESTED)

/* libnl < 3.11.0 does not implement nla_get_uint() */
uint64_t ovpn_nla_get_uint(struct nlattr *attr)
{
    if (nla_len(attr) == sizeof(uint32_t))
        return nla_get_u32(attr);
    else
        return nla_get_u64(attr);
}

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

struct OvpnDcoPeer
{
    typedef RCPtr<struct OvpnDcoPeer> Ptr;
    __u32 id;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    __u16 local_port;
    struct sockaddr_storage remote;
    struct
    {
        __u32 interval;
        __u32 timeout;
    } keepalive;
    struct
    {
        __u64 rx_bytes, tx_bytes;
        __u32 rx_pkts, tx_pkts;
    } vpn;
    struct
    {
        __u64 rx_bytes, tx_bytes;
        __u32 rx_pkts, tx_pkts;
    } transport;
};

/**
 * Implements asynchronous communication with ovpn-dco kernel module
 * via generic netlink protocol.
 *
 * Before using this class, caller should create ovpn-dco network device.
 *
 * @tparam ReadHandler class which implements
 * <tt>tun_read_handler(BufferAllocated &buf)</tt> method. \n
 *
 * buf has following layout:
 *  \li first byte - command type ( \p OVPN_CMD_DEL_PEER or -1 for error)
 *  \li following bytes - command-specific payload
 */
template <typename ReadHandler>
class GeNL : public RC<thread_unsafe_refcount>
{
    OPENVPN_EXCEPTION(netlink_error);

    typedef std::unique_ptr<nl_msg, decltype(&nlmsg_free)> NlMsgPtr;
    typedef std::unique_ptr<nl_sock, decltype(&nl_socket_free)> NlSockPtr;
    typedef std::unique_ptr<nl_cb, decltype(&nl_cb_put)> NlCbPtr;

  public:
    typedef RCPtr<GeNL> Ptr;

    /**
     * Detect ovpn-dco kernel module
     *
     * @returns bool value indicating whether the module is loaded
     */
    static bool available()
    {
        NlSockPtr sock_ptr(nl_socket_alloc(), nl_socket_free);

        int nl_family_id = -1;
        if (sock_ptr && genl_connect(sock_ptr.get()) == 0)
            nl_family_id = genl_ctrl_resolve(sock_ptr.get(), OVPN_FAMILY_NAME);

        return nl_family_id >= 0;
    }

    /**
     * Construct a new GeNL object
     *
     * @param io_context reference to io_context
     * @param ifindex_arg index of ovpn-dco network device
     * @param read_handler_arg instance of \p ReadHandler
     * @throws netlink_error thrown if error occurs during initialization
     */
    explicit GeNL(openvpn_io::io_context &io_context,
                  unsigned int ifindex_arg,
                  ReadHandler read_handler_arg)
        : sock_ptr(nl_socket_alloc(), nl_socket_free),
          cb_ptr(nl_cb_alloc(NL_CB_DEFAULT), nl_cb_put),
          sock(sock_ptr.get()),
          cb(cb_ptr.get()),
          ifindex(ifindex_arg),
          read_handler(read_handler_arg),
          halt(false)
    {
        nl_socket_set_buffer_size(sock, 8192, 8192);

        int ret = genl_connect(sock);
        if (ret != 0)
            OPENVPN_THROW(netlink_error,
                          " cannot connect to generic netlink: " << nl_geterror(ret));

        ret = 1;
        if (setsockopt(nl_socket_get_fd(sock), SOL_NETLINK, NETLINK_EXT_ACK, &ret, sizeof(ret)) < 0)
            OPENVPN_THROW(netlink_error,
                          " cannot enable NETLINK_EXT_ACK on socket: " << errno);

        int mcast_id = get_mcast_id();
        if (mcast_id < 0)
            OPENVPN_THROW(netlink_error,
                          " cannot get multicast group: " << nl_geterror(mcast_id));

        ret = nl_socket_add_membership(sock, mcast_id);
        if (ret)
            OPENVPN_THROW(netlink_error, "failed to join mcast group: " << ret);

        ovpn_dco_id = genl_ctrl_resolve(sock, OVPN_FAMILY_NAME);
        if (ovpn_dco_id < 0)
            OPENVPN_THROW(netlink_error,
                          " cannot find ovpn_dco netlink component: " << ovpn_dco_id);

        // set callback to handle control channel messages
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, message_received, this);

        // clang-format off
        nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
            [](struct nl_msg *, void *) -> int
            { return NL_OK; },
            NULL);
        // clang-format on

        nl_socket_set_cb(sock, cb);

        // wrap netlink socket into ASIO primitive for async read
        stream.reset(new openvpn_io::posix::stream_descriptor(
            io_context, nl_socket_get_fd(sock)));

        nl_socket_set_nonblocking(sock);

        queue_genl_read();
    }

    /**
     * Add peer information to kernel module
     *
     * @param peer_id Peer ID of the peer being created
     * @param fd socket to be used to communicate with the peer
     * @param sa sockaddr object representing the remote endpoint
     * @param salen length of sa (either sizeof(sockaddr_in) or
     * sizeof(sockaddr_in6)
     * @param vpn4 IPv4 address associated with this peer in the tunnel
     * @param vpn6 IPv6 address associated with this peer in the tunnel
     *
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void new_peer(int peer_id,
                  int fd,
                  struct sockaddr *sa,
                  socklen_t salen,
                  IPv4::Addr vpn4,
                  IPv6::Addr vpn6)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        auto msg_ptr = create_msg(OVPN_CMD_PEER_NEW);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_PEER);

        NLA_PUT_U32(msg, OVPN_A_PEER_ID, peer_id);
        NLA_PUT_U32(msg, OVPN_A_PEER_SOCKET, fd);
        if (sa->sa_family == AF_INET)
        {
            NLA_PUT_U32(msg, OVPN_A_PEER_REMOTE_IPV4, sin->sin_addr.s_addr);
        }
        else if (sa->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
            NLA_PUT(msg, OVPN_A_PEER_REMOTE_IPV6, sizeof(sin6->sin6_addr), &sin6->sin6_addr);
            NLA_PUT_U32(msg, OVPN_A_PEER_REMOTE_IPV6_SCOPE_ID, sin6->sin6_scope_id);
        }
        else
        {
            OPENVPN_THROW(netlink_error, " new_peer() bogus remote address family " << sa->sa_family);
        }
        NLA_PUT_U16(msg, OVPN_A_PEER_REMOTE_PORT, sin->sin_port);

        if (vpn4.specified())
        {
            NLA_PUT_U32(msg, OVPN_A_PEER_VPN_IPV4, vpn4.to_uint32_net());
        }

        if (vpn6.specified())
        {
            struct in6_addr addr6 = vpn6.to_in6_addr();
            NLA_PUT(msg, OVPN_A_PEER_VPN_IPV6, sizeof(addr6), &addr6);
        }

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " new_peer() nla_put_failure");
    }

    /**
     * Inject new key into kernel module
     *
     * @param key_slot OVPN_KEY_SLOT_PRIMARY or OVPN_KEY_SLOT_SECONDARY
     * @param kc pointer to KeyConfig struct which contains key data
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void new_key(unsigned int key_slot, const KoRekey::KeyConfig *kc)
    {
        auto msg_ptr = create_msg(OVPN_CMD_KEY_NEW);
        auto *msg = msg_ptr.get();

        const int NONCE_TAIL_LEN = 8;

        struct nlattr *key_dir;

        struct nlattr *attr = nla_nest_start(msg, OVPN_A_KEYCONF);
        if (!attr)
            OPENVPN_THROW(netlink_error, " new_key() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_KEYCONF_PEER_ID, kc->remote_peer_id);
        NLA_PUT_U32(msg, OVPN_A_KEYCONF_SLOT, key_slot);
        NLA_PUT_U32(msg, OVPN_A_KEYCONF_KEY_ID, kc->key_id);
        NLA_PUT_U32(msg, OVPN_A_KEYCONF_CIPHER_ALG, kc->cipher_alg);

        key_dir = nla_nest_start(msg, OVPN_A_KEYCONF_ENCRYPT_DIR);
        if (!key_dir)
            OPENVPN_THROW(netlink_error,
                          " new_key() cannot allocate encrypt key submessage");

        NLA_PUT(msg, OVPN_A_KEYDIR_CIPHER_KEY, kc->encrypt.cipher_key_size, kc->encrypt.cipher_key);
        if (kc->cipher_alg == OVPN_CIPHER_ALG_AES_GCM
            || kc->cipher_alg == OVPN_CIPHER_ALG_CHACHA20_POLY1305)
        {
            NLA_PUT(msg, OVPN_A_KEYDIR_NONCE_TAIL, NONCE_TAIL_LEN, kc->encrypt.nonce_tail);
        }
        nla_nest_end(msg, key_dir);

        key_dir = nla_nest_start(msg, OVPN_A_KEYCONF_DECRYPT_DIR);
        if (!key_dir)
            OPENVPN_THROW(netlink_error,
                          " new_key() cannot allocate decrypt key submessage");

        NLA_PUT(msg, OVPN_A_KEYDIR_CIPHER_KEY, kc->decrypt.cipher_key_size, kc->decrypt.cipher_key);
        if (kc->cipher_alg == OVPN_CIPHER_ALG_AES_GCM
            || kc->cipher_alg == OVPN_CIPHER_ALG_CHACHA20_POLY1305)
        {
            NLA_PUT(msg, OVPN_A_KEYDIR_NONCE_TAIL, NONCE_TAIL_LEN, kc->decrypt.nonce_tail);
        }
        nla_nest_end(msg, key_dir);

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " new_key() nla_put_failure");
    }

    /**
     * Swap keys between primary and secondary slots. Called
     * by client as part of rekeying logic to promote and demote keys.
     *
     * @param peer_id the ID of the peer whose keys have to be swapped
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void swap_keys(int peer_id)
    {
        auto msg_ptr = create_msg(OVPN_CMD_KEY_SWAP);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_KEYCONF);
        if (!attr)
            OPENVPN_THROW(netlink_error, " swap_keys() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_KEYCONF_PEER_ID, peer_id);

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " swap_keys() nla_put_failure");
    }

    /**
     * Remove key from key slot.
     *
     * @param peer_id the ID of the peer whose keys has to be deleted
     * @param key_slot OVPN_KEY_SLOT_PRIMARY or OVPN_KEY_SLOT_SECONDARY
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void del_key(int peer_id, unsigned int key_slot)
    {
        auto msg_ptr = create_msg(OVPN_CMD_KEY_DEL);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_KEYCONF);
        if (!attr)
            OPENVPN_THROW(netlink_error, " del_key() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_KEYCONF_PEER_ID, peer_id);
        NLA_PUT_U8(msg, OVPN_A_KEYCONF_SLOT, static_cast<uint8_t>(key_slot));

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " del_key() nla_put_failure");
    }

    /**
     * Set peer properties. Currently used for keepalive settings.
     *
     * @param peer_id ID of the peer whose properties have to be modified
     * @param keepalive_interval how often to send ping packet in absence of
     * traffic
     * @param keepalive_timeout when to trigger keepalive_timeout in absence of
     * traffic
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void set_peer(int peer_id, unsigned int keepalive_interval, unsigned int keepalive_timeout)
    {
        auto msg_ptr = create_msg(OVPN_CMD_PEER_SET);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_PEER);
        if (!attr)
            OPENVPN_THROW(netlink_error, " set_peer() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_PEER_ID, peer_id);
        NLA_PUT_U32(msg, OVPN_A_PEER_KEEPALIVE_INTERVAL, keepalive_interval);
        NLA_PUT_U32(msg, OVPN_A_PEER_KEEPALIVE_TIMEOUT, keepalive_timeout);

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " set_peer() nla_put_failure");
    }

    /**
     * Delete an existing peer.
     *
     * @param peer_id the ID of the peer to delete
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void del_peer(int peer_id)
    {
        auto msg_ptr = create_msg(OVPN_CMD_PEER_DEL);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_PEER);
        if (!attr)
            OPENVPN_THROW(netlink_error, " del_peer() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_PEER_ID, peer_id);

        nla_nest_end(msg, attr);

        send_netlink_message(msg);
        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " del_peer() nla_put_failure");
    }

    /**
     * Retrieve he current status of a peer.
     *
     * @param peer_id the ID of the peer to query
     * @param sync When true the method waits for the reply before returning
     * @throws netlink_error thrown if error occurs during sending netlink message
     */
    void get_peer(int peer_id, bool sync)
    {
        auto msg_ptr = create_msg(OVPN_CMD_PEER_GET);
        auto *msg = msg_ptr.get();
        struct nlattr *attr = nla_nest_start(msg, OVPN_A_PEER);
        if (!attr)
            OPENVPN_THROW(netlink_error, " get_peer() cannot allocate submessage");

        NLA_PUT_U32(msg, OVPN_A_PEER_ID, peer_id);

        nla_nest_end(msg, attr);

        nl_status = 1;
        send_netlink_message(msg);

        /* if the user has requested a synchronous execution, wait for the reply and parse
         * it here directly
         */
        while (sync && nl_status == 1)
        {
            stream->wait(openvpn_io::posix::stream_descriptor::wait_read);
            read_netlink_message();
        }

        return;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " get_peer() nla_put_failure");
    }

    void stop()
    {
        if (!halt)
        {
            halt = true;

            try
            {
                stream->cancel();
                stream->close();
            }
            catch (...)
            {
                // ASIO might throw transport exceptions which I found is safe to ignore
            }

            // contrary to what ASIO doc says, stream->close() doesn't
            // cancel async read on netlink socket, explicitly close it here
            sock_ptr.reset();
            cb_ptr.reset();
        }
    }

  private:
    struct mcast_handler_args
    {
        const char *group;
        int id;
    };

    /**
     * This callback is called by libnl. Here we enumerate netlink
     * multicast groups and find id of the one which name matches
     * ovpn-dco multicast group.
     *
     * @param msg netlink message to be processed
     * @param arg arguments passed by nl_cb_set() call
     * @return int id of ovpn-dco multicast group
     */
    static int mcast_family_handler(struct nl_msg *msg, void *arg)
    {
        struct mcast_handler_args *grp = static_cast<mcast_handler_args *>(arg);
        struct nlattr *tb[CTRL_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(
            nlmsg_data(reinterpret_cast<const nlmsghdr *>(nlmsg_hdr(msg))));
        struct nlattr *mcgrp;
        int rem_mcgrp;

        nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[CTRL_ATTR_MCAST_GROUPS])
            return NL_SKIP;

        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp)
        {
            struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

            nla_parse(tb_mcgrp,
                      CTRL_ATTR_MCAST_GRP_MAX,
                      static_cast<nlattr *>(nla_data(mcgrp)),
                      nla_len(mcgrp),
                      NULL);

            if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] || !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
                continue;
            if (strncmp((const char *)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                        grp->group,
                        nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
                continue;
            grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
            break;
        }

        return NL_SKIP;
    }

    /**
     * Return id of multicast group which ovpn uses to
     * broadcast OVPN_CMD_*_NTF messages
     *
     * @return int multicast group id
     */
    int get_mcast_id()
    {
        int ret = 1;
        struct mcast_handler_args grp = {
            .group = OVPN_MCGRP_PEERS,
            .id = -ENOENT,
        };
        NlMsgPtr msg_ptr(nlmsg_alloc(), nlmsg_free);
        auto *msg = msg_ptr.get();

        NlCbPtr mcast_cb_ptr(nl_cb_alloc(NL_CB_DEFAULT), nl_cb_put);
        auto *mcast_cb = mcast_cb_ptr.get();

        int ctrlid = genl_ctrl_resolve(sock, "nlctrl");

        genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);
        NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, OVPN_FAMILY_NAME);

        send_netlink_message(msg);

        // clang-format off
        nl_cb_err(mcast_cb, NL_CB_CUSTOM,
                  [](struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) -> int
                  {
                          int *ret = static_cast<int *>(arg);
                          *ret = err->error;
                          return NL_STOP; },
                  &ret);
        nl_cb_set(mcast_cb, NL_CB_ACK, NL_CB_CUSTOM,
                  [](struct nl_msg *msg, void *arg) -> int
                  {
                          int *ret = static_cast<int *>(arg);
                          *ret = 0;
                          return NL_STOP; },
                  &ret);
        // clang-format on

        nl_cb_set(mcast_cb, NL_CB_VALID, NL_CB_CUSTOM, mcast_family_handler, &grp);

        while (ret > 0)
            nl_recvmsgs(sock, mcast_cb);

        if (ret == 0)
            ret = grp.id;

        return ret;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, "get_mcast_id() nla_put_failure");
    }

    void handle_read(const openvpn_io::error_code &error)
    {
        if (halt)
            return;

        std::ostringstream os;
        if (error)
        {
            os << "error reading netlink message: " << error.message() << ", "
               << error;
            reset_buffer();
            int8_t cmd = -1;
            buf.write(&cmd, sizeof(cmd));
            buf_write_string(buf, os.str());
            read_handler->tun_read_handler(buf);
        }

        try
        {
            read_netlink_message();
            queue_genl_read();
        }
        catch (const netlink_error &e)
        {
            reset_buffer();
            int8_t cmd = -1;
            buf.write(&cmd, sizeof(cmd));
            buf_write_string(buf, e.what());
            read_handler->tun_read_handler(buf);
        }
    }

    void queue_genl_read()
    {
        stream->async_wait(openvpn_io::posix::stream_descriptor::wait_read,
                           [self = Ptr(this)](const openvpn_io::error_code &error)
                           {
                               self->handle_read(error);
                           });
    }

    NlMsgPtr create_msg(int cmd)
    {
        NlMsgPtr msg_ptr(nlmsg_alloc(), nlmsg_free);
        genlmsg_put(msg_ptr.get(), 0, 0, ovpn_dco_id, 0, 0, cmd, 0);
        NLA_PUT_U32(msg_ptr.get(), OVPN_A_IFINDEX, ifindex);
        return msg_ptr;

    nla_put_failure:
        OPENVPN_THROW(netlink_error, " create_msg() nla_put_failure");
    }

    void read_netlink_message()
    {
        // this is standard error code returned from kernel
        // and assigned inside ovpn_nl_cb_error()
        int ovpn_dco_err = 0;
        nl_cb_err(cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &ovpn_dco_err);

        // this triggers reading callback, GeNL::message_received(),
        // and, if neccessary, ovpn_nl_cb_error() and returns netlink error code
        int netlink_err = nl_recvmsgs(sock, cb);

        if (ovpn_dco_err != 0)
            OPENVPN_THROW(netlink_error,
                          "ovpn-dco error on receiving message: "
                              << strerror(-ovpn_dco_err) << ", " << ovpn_dco_err);

        if (netlink_err < 0)
            OPENVPN_THROW(netlink_error,
                          "netlink error on receiving message: "
                              << nl_geterror(netlink_err) << ", " << netlink_err);
    }

    /**
     * This is called inside libnl's \c nl_recvmsgs() call
     * to process incoming netlink message.
     *
     * @param msg netlink message to be processed
     * @param arg argument passed by \c nl_cb_set()
     * @return int callback action
     */
    static int message_received(struct nl_msg *msg, void *arg)
    {
        GeNL *self = static_cast<GeNL *>(arg);
        int ret;

        struct genlmsghdr *gnlh = static_cast<genlmsghdr *>(
            nlmsg_data(reinterpret_cast<const nlmsghdr *>(nlmsg_hdr(msg))));
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[OVPN_A_MAX + 1];

        if (!genlmsg_valid_hdr(nlh, 0))
        {
            OPENVPN_LOG("ovpn-dco: invalid header");
            return NL_SKIP;
        }

        if (nla_parse(attrs, OVPN_A_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL))
        {
            OPENVPN_LOG("received bogus data from ovpn-dco");
            return NL_SKIP;
        }

        switch (gnlh->cmd)
        {
        case OVPN_CMD_PEER_DEL_NTF:
            if (!attrs[OVPN_A_IFINDEX])
            {
                OPENVPN_LOG("missing OVPN_A_IFINDEX attribute in message");
                return NL_SKIP;
            }

            if (self->ifindex != nla_get_u32(attrs[OVPN_A_IFINDEX]))
                return NL_SKIP;

            if (!attrs[OVPN_A_PEER])
                OPENVPN_THROW(netlink_error, "missing OVPN_A_PEER attribute in "
                                             "OVPN_CMD_PEER_DEL_NTF message");

            struct nlattr *del_peer_attrs[OVPN_A_PEER_MAX + 1];
            ret = nla_parse_nested(del_peer_attrs, OVPN_A_PEER_MAX, attrs[OVPN_A_PEER], NULL);
            if (ret)
                OPENVPN_THROW(netlink_error,
                              "cannot parse OVPN_A_PEER attribute");

            if (!del_peer_attrs[OVPN_A_PEER_ID] || !del_peer_attrs[OVPN_A_PEER_DEL_REASON])
                OPENVPN_THROW(netlink_error, "missing attributes in OVPN_CMD_PEER_DEL_NTF");

            self->reset_buffer();
            self->buf.write(&gnlh->cmd, sizeof(gnlh->cmd));

            {
                uint32_t peer_id = nla_get_u32(del_peer_attrs[OVPN_A_PEER_ID]);
                self->buf.write(&peer_id, sizeof(peer_id));
            }

            {
                uint8_t reason = nla_get_u8(del_peer_attrs[OVPN_A_PEER_DEL_REASON]);
                self->buf.write(&reason, sizeof(reason));
            }

            self->read_handler->tun_read_handler(self->buf);
            break;

        case OVPN_CMD_PEER_GET:
            {
                if (!attrs[OVPN_A_PEER])
                    OPENVPN_THROW(netlink_error, "missing OVPN_A_PEER attribute in "
                                                 "OVPN_CMD_PEER_GET command reply");

                struct nlattr *get_peer_attrs[OVPN_A_PEER_MAX + 1];
                ret = nla_parse_nested(get_peer_attrs, OVPN_A_PEER_MAX, attrs[OVPN_A_PEER], NULL);
                if (ret)
                    OPENVPN_THROW(netlink_error, "cannot parse OVPN_A_PEER attribute");

                if (!get_peer_attrs[OVPN_A_PEER_ID])
                    OPENVPN_THROW(netlink_error, "missing attribute PEER_ID in OVPN_CMD_PEER_GET reply");

                struct OvpnDcoPeer peer = {0};
                peer.id = nla_get_u32(get_peer_attrs[OVPN_A_PEER_ID]);

                /* peer.remote is expected to contain the remote endpoint encoded in a
                 * sockaddr object. However, ovpn now sends us address, port and scope_id
                 * all separated, which means we need to manually "build" a sockaddr here.
                 * Since peer.remote is currently unused in the rest of the codebase, we
                 * can postpone this complexity.
                 *
                 * TODO: fill peer.remote with a sockaddr object built out of the remote
                 * attrs send by ovpn
                 */

                if (get_peer_attrs[OVPN_A_PEER_VPN_IPV4])
                {
                    memcpy(&peer.ipv4, nla_data(get_peer_attrs[OVPN_A_PEER_VPN_IPV4]), sizeof(peer.ipv4));
                }
                if (get_peer_attrs[OVPN_A_PEER_VPN_IPV6])
                {
                    memcpy(&peer.ipv6, nla_data(get_peer_attrs[OVPN_A_PEER_VPN_IPV6]), sizeof(peer.ipv6));
                }

                peer.local_port = nla_get_u16(get_peer_attrs[OVPN_A_PEER_LOCAL_PORT]);

                peer.keepalive.interval = nla_get_u32(get_peer_attrs[OVPN_A_PEER_KEEPALIVE_INTERVAL]);
                peer.keepalive.timeout = nla_get_u32(get_peer_attrs[OVPN_A_PEER_KEEPALIVE_TIMEOUT]);
                peer.vpn.rx_bytes = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_VPN_RX_BYTES]);
                peer.vpn.tx_bytes = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_VPN_TX_BYTES]);
                peer.vpn.rx_pkts = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_VPN_RX_PACKETS]);
                peer.vpn.tx_pkts = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_VPN_TX_PACKETS]);

                peer.transport.rx_bytes = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_LINK_RX_BYTES]);
                peer.transport.tx_bytes = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_LINK_TX_BYTES]);
                peer.transport.rx_pkts = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_LINK_RX_PACKETS]);
                peer.transport.tx_pkts = ovpn_nla_get_uint(get_peer_attrs[OVPN_A_PEER_LINK_TX_PACKETS]);

                self->reset_buffer();
                self->buf.write(&gnlh->cmd, sizeof(gnlh->cmd));
                self->buf.write(&peer, sizeof(peer));

                self->read_handler->tun_read_handler(self->buf);
                /* report to the other context that the reply has been received */
                nl_status = 0;
                break;
            }
        default:
            OPENVPN_LOG(__func__ << " unknown netlink command: " << (int)gnlh->cmd);
        }

        return NL_SKIP;
    }

    void reset_buffer()
    {
        // good enough values to handle control packets
        buf.reset(512, 3072, BufAllocFlags::GROW | BufAllocFlags::CONSTRUCT_ZERO | BufAllocFlags::DESTRUCT_ZERO);
    }

    /**
     * This is an error callback called by netlink for
     * error message processing customization.
     *
     * @param nla netlink address of the peer (value not needed here)
     * @param err netlink error message being processed
     * @param arg argument passed by \c nl_cb_err()
     * @return int callback action
     */
    static int ovpn_nl_cb_error(struct sockaddr_nl *nla,
                                struct nlmsgerr *err,
                                void *arg)
    {
        struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
        struct nlattr *tb_msg[OVPN_NLMSGERR_ATTR_MAX + 1];
        int len = nlh->nlmsg_len;
        struct nlattr *attrs;
        int *ret = static_cast<int *>(arg);
        int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

        *ret = err->error;

        if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
            return NL_STOP;

        if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
            ack_len += static_cast<int>(err->msg.nlmsg_len - sizeof(*nlh));

        if (len <= ack_len)
            return NL_STOP;

        attrs = reinterpret_cast<nlattr *>((unsigned char *)nlh + ack_len);
        len -= ack_len;

        nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
        if (tb_msg[NLMSGERR_ATTR_MSG])
        {
            OPENVPN_LOG(__func__ << " kernel error "
                                 << (char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
        }

        if (tb_msg[OVPN_NLMSGERR_ATTR_MISS_NEST])
        {
            OPENVPN_LOG(__func__ << "missing required nesting type "
                                 << nla_get_u32(tb_msg[OVPN_NLMSGERR_ATTR_MISS_NEST]));
        }

        if (tb_msg[OVPN_NLMSGERR_ATTR_MISS_TYPE])
        {
            OPENVPN_LOG(__func__ << "missing required attribute type "
                                 << nla_get_u32(tb_msg[OVPN_NLMSGERR_ATTR_MISS_TYPE]));
        }

        return NL_STOP;
    }

    void send_netlink_message(struct nl_msg *msg)
    {
        int netlink_err = nl_send_auto(sock, msg);

        if (netlink_err < 0)
            OPENVPN_THROW(netlink_error,
                          "netlink error on sending message: "
                              << nl_geterror(netlink_err) << ", " << netlink_err);
    }

    NlSockPtr sock_ptr;
    NlCbPtr cb_ptr;

    struct nl_sock *sock;
    struct nl_cb *cb;

    int ovpn_dco_id;
    unsigned int ifindex;

    ReadHandler read_handler;

    bool halt;
    BufferAllocated buf;

    std::unique_ptr<openvpn_io::posix::stream_descriptor> stream;
    static int nl_status;
};

template <typename ReadHandler>
int GeNL<ReadHandler>::nl_status = 0;

} // namespace openvpn
