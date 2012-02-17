#ifndef OPENVPN_TRANSPORT_SOCKET_PROTECT_H
#define OPENVPN_TRANSPORT_SOCKET_PROTECT_H

namespace openvpn {
  // Used as an interface in cases where the high-level controlling app
  // needs early access to newly created transport sockets for making
  // property changes.  For example, on Android, we need to "protect"
  // the socket from being routed into the VPN tunnel.
  class SocketProtect {
  public:
    virtual bool socket_protect(int socket) = 0;
  };
}

#endif
