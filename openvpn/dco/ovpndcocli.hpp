//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
//    Copyright (C) 2020-2020 Lev Stipakov <lev@openvpn.net>
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

// tun/transport client for ovpn-dco

class OvpnDcoClient : public Client, public KoRekey::Receiver {
  friend class ClientConfig;
  friend class GeNL;

  typedef RCPtr<OvpnDcoClient> Ptr;
  typedef GeNL<OvpnDcoClient *> GeNLImpl;

public:
  virtual void tun_start(const OptionList &opt, TransportClient &transcli,
                         CryptoDCSettings &dc_settings) override {
    // notify parent
    tun_parent->tun_pre_tun_config();

    // parse pushed options
    TunBuilderCapture::Ptr po;
    TunBuilderBase *builder;

    po.reset(new TunBuilderCapture());
    builder = po.get();

    TunProp::configure_builder(
        builder, state.get(), config->transport.stats.get(),
        server_endpoint_addr(), config->tun.tun_prop, opt, nullptr, false);

    if (po)
      OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string());

    ActionList::Ptr add_cmds = new ActionList();
    remove_cmds.reset(new ActionListReversed());

    std::vector<IP::Route> rtvec;

    TUN_LINUX::tun_config(config->dev_name, *po, &rtvec, *add_cmds,
                          *remove_cmds, true);

    // execute commands to bring up interface
    add_cmds->execute_log();

    // Add a hook so ProtoContext will call back to
    // rekey() on rekey ops.
    dc_settings.set_factory(CryptoDCFactory::Ptr(new KoRekey::Factory(
        dc_settings.factory(), this, config->transport.frame)));

    // signal that we are connected
    tun_parent->tun_connected();
  }

  virtual std::string tun_name() const override { return "ovpn-dco"; }

  virtual void transport_start() override { transport_start_udp(); }

  virtual bool transport_send_const(const Buffer &buf) override {
    return send(buf);
  }

  virtual bool transport_send(BufferAllocated &buf) override {
    return send(buf);
  }

  bool send(const Buffer &buf) {
    genl->send_data(buf.c_data(), buf.size());
    return true;
  }

  virtual void start_impl_udp(const openvpn_io::error_code &error) override {
    if (halt)
      return;

    if (!error) {
      auto &sock = udp().socket;
      auto local = sock.local_endpoint();
      auto remote = sock.remote_endpoint();

      std::ostringstream os;
      int res = TunNetlink::iface_new(os, config->dev_name, "ovpn-dco");
      if (res != 0) {
        stop_();
        transport_parent->transport_error(Error::TUN_IFACE_CREATE, os.str());
      } else {
        genl.reset(new GeNLImpl(
            io_context, if_nametoindex(config->dev_name.c_str()), this));

        genl->start_vpn(sock.native_handle());
        genl->new_peer(local, remote);

        transport_parent->transport_connecting();
      }
    } else {
      std::ostringstream os;
      os << "UDP connect error on '" << server_host << ':' << server_port
         << "' (" << udp().server_endpoint << "): " << error.message();
      config->transport.stats->error(Error::UDP_CONNECT_ERROR);
      stop_();
      transport_parent->transport_error(Error::UNDEF, os.str());
    }
  }

  virtual void stop_() override {
    if (!halt) {
      halt = true;
      if (genl)
        genl->stop();
      std::ostringstream os;
      int res = TunNetlink::iface_del(os, config->dev_name);
      if (res != 0) {
        OPENVPN_LOG("ovpndcocli: error deleting iface ovpn:" << os.str());
      }
    }
  }

  virtual void rekey(const CryptoDCInstance::RekeyType rktype,
                     const KoRekey::Info &rkinfo) override {
    if (halt)
      return;

    rekey_impl(rktype, rkinfo);
  }

  void rekey_impl(const CryptoDCInstance::RekeyType rktype,
                  const KoRekey::Info &rkinfo) {
    KoRekey::OvpnDcoKey key(rktype, rkinfo);
    auto kc = key();

    switch (rktype) {
    case CryptoDCInstance::ACTIVATE_PRIMARY:
      genl->new_key(OVPN_KEY_SLOT_PRIMARY, kc);
      break;

    case CryptoDCInstance::NEW_SECONDARY:
      genl->new_key(OVPN_KEY_SLOT_SECONDARY, kc);
      break;

    case CryptoDCInstance::PRIMARY_SECONDARY_SWAP:
      genl->swap_keys();
      break;

    case CryptoDCInstance::DEACTIVATE_SECONDARY:
      genl->del_key(OVPN_KEY_SLOT_SECONDARY);
      break;

    case CryptoDCInstance::DEACTIVATE_ALL:
      // TODO: deactivate all keys
      OPENVPN_LOG("ovpndcocli: deactivate all keys");
      break;

    default:
      OPENVPN_LOG("ovpndcocli: unknown rekey type: " << rktype);
      break;
    }
  }

  bool tun_read_handler(BufferAllocated &buf) {
    if (halt)
      return false;

    int8_t cmd = -1;
    buf.read(&cmd, sizeof(cmd));

    switch (cmd) {
    case OVPN_CMD_PACKET:
      transport_parent->transport_recv(buf);
      break;

    case OVPN_CMD_DEL_PEER: {
      stop_();
      int8_t reason = -1;
      buf.read(&reason, sizeof(reason));
      switch (reason) {
      case OVPN_DEL_PEER_REASON_EXPIRED:
        transport_parent->transport_error(Error::TRANSPORT_ERROR,
                                          "keepalive timeout");
        break;

      default:
        std::ostringstream os;
        os << "peer deleted, reason " << reason;
        transport_parent->transport_error(Error::TUN_HALT, os.str());
        break;
      }
      break;
    }

    case -1:
      // consider all errors as fatal
      stop_();
      transport_parent->transport_error(Error::TUN_HALT, buf_to_string(buf));
      return false;
      break;

    default:
      OPENVPN_LOG("Unknown ovpn-dco cmd " << cmd);
      break;
    }

    return true;
  }

private:
  OvpnDcoClient(openvpn_io::io_context &io_context_arg,
                ClientConfig *config_arg, TransportClientParent *parent_arg)
      : Client(io_context_arg, config_arg, parent_arg) {}

  GeNLImpl::Ptr genl;
};