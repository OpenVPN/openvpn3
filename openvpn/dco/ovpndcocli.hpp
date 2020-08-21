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

class OvpnDcoClient : public Client {
  friend class ClientConfig;

  typedef RCPtr<OvpnDcoClient> Ptr;

public:
  virtual void tun_start(const OptionList &opt, TransportClient &transcli,
                         CryptoDCSettings &dc_settings) override {}

  virtual std::string tun_name() const override { return "ovpn-dco"; }

  virtual void transport_start() override {
    std::ostringstream os;
    int res = TunNetlink::iface_new(os, config->dev_name, "ovpn-dco");
    if (res != 0) {
      stop_();
      transport_parent->transport_error(Error::TUN_IFACE_CREATE, os.str());
    } else {
      transport_start_udp();
    }
  }

  virtual bool transport_send_const(const Buffer &buf) override {
    return false;
  }

  virtual bool transport_send(BufferAllocated &buf) override { return false; }

  virtual void start_impl_udp(const openvpn_io::error_code &error) override {
    if (!halt) {
      if (!error) {
        transport_parent->transport_connecting();
      } else {
        std::ostringstream os;
        os << "UDP connect error on '" << server_host << ':' << server_port
           << "' (" << udp().server_endpoint << "): " << error.message();
        config->transport.stats->error(Error::UDP_CONNECT_ERROR);
        stop_();
        transport_parent->transport_error(Error::UNDEF, os.str());
      }
    }
  }

  virtual void stop_() override {
    if (!halt) {
      std::ostringstream os;
      int res = TunNetlink::iface_del(os, config->dev_name);
      if (res != 0) {
        OPENVPN_LOG("ovpndcocli: error deleting iface ovpn:" << os.str());
      }
    }
  }

private:
  OvpnDcoClient(openvpn_io::io_context &io_context_arg,
                ClientConfig *config_arg, TransportClientParent *parent_arg)
      : Client(io_context_arg, config_arg, parent_arg) {}
};