//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
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

namespace openvpn {
namespace DCOTransport {
class ProtoBase : public virtual RC<thread_unsafe_refcount> {
public:
  typedef RCPtr<ProtoBase> Ptr;

  virtual IP::Addr server_endpoint_addr() const = 0;
  virtual void close() = 0;
  virtual void get_endpoint(RemoteList::Ptr remote_list) = 0;
  virtual void open() = 0;
  virtual const char *proto() = 0;
  virtual int native_handle() = 0;
  virtual void
      async_connect(std::function<void(const openvpn_io::error_code &)>&&) = 0;
  virtual openvpn_io::ip::address local_address() = 0;
  virtual openvpn_io::ip::address remote_address() = 0;
  virtual unsigned short local_port() = 0;
  virtual unsigned short remote_port() = 0;
};

template <class ENDPOINT, class SOCKET> class ProtoImpl : public ProtoBase {
public:
  explicit ProtoImpl(openvpn_io::io_context &io_context)
      : resolver(io_context), socket(io_context) {}

  virtual IP::Addr server_endpoint_addr() const override {
    return IP::Addr::from_asio(server_endpoint.address());
  }

  virtual void close() override {
    socket.close();
    resolver.cancel();
  }

  virtual void get_endpoint(RemoteList::Ptr remote_list) override {
    remote_list->get_endpoint(server_endpoint);
  }

  virtual void open() override { socket.open(server_endpoint.protocol()); }

  virtual const char *proto() override { return "UDP"; }

  virtual int native_handle() override { return socket.native_handle(); }

  virtual void async_connect(
      std::function<void(const openvpn_io::error_code &)>&& func) override {
    socket.async_connect(server_endpoint, func);
  }

  virtual openvpn_io::ip::address local_address() override {
    return socket.local_endpoint().address();
  }

  virtual openvpn_io::ip::address remote_address() override {
    return socket.remote_endpoint().address();
  }

  virtual unsigned short local_port() override {
    return socket.local_endpoint().port();
  }

  virtual unsigned short remote_port() override {
    return socket.remote_endpoint().port();
  }

protected:
  openvpn_io::ip::udp::resolver resolver;
  SOCKET socket;
  ENDPOINT server_endpoint;
};

class UDP : public ProtoImpl<UDPTransport::AsioEndpoint,
                             openvpn_io::ip::udp::socket> {
public:
  explicit UDP(openvpn_io::io_context &io_context) : ProtoImpl(io_context) {}
};

class TCP : public ProtoImpl<openvpn_io::ip::tcp::endpoint,
                             openvpn_io::ip::tcp::socket> {
public:
  explicit TCP(openvpn_io::io_context &io_context) : ProtoImpl(io_context) {}
};

} // namespace DCOTransport
} // namespace openvpn
