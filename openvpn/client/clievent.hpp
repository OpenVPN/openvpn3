//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// This file describes the basic set of OpenVPN client events, including the
// normal events leading up to a connection as well as error events.

#ifndef OPENVPN_CLIENT_CLIEVENT_H
#define OPENVPN_CLIENT_CLIEVENT_H

#include <sstream>
#include <deque>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/transport/protocol.hpp>

namespace openvpn {
  namespace ClientEvent {
    enum Type {
      // normal events including disconnected, connected, and other transitional events
      DISCONNECTED=0,
      CONNECTED,
      RECONNECTING,
      RESOLVE,
      WAIT,
      WAIT_PROXY,
      CONNECTING,
      GET_CONFIG,
      ASSIGN_IP,
      ADD_ROUTES,
      PAUSE,
      RESUME,

      // start of errors, must be marked by ERROR_START below
      AUTH_FAILED,
      CERT_VERIFY_FAIL,
      TLS_VERSION_MIN,
      CLIENT_HALT,
      CLIENT_RESTART,
      CONNECTION_TIMEOUT,
      INACTIVE_TIMEOUT,
      DYNAMIC_CHALLENGE,
      PROXY_NEED_CREDS,
      PROXY_ERROR,
      TUN_SETUP_FAILED,
      TUN_IFACE_CREATE,
      TUN_IFACE_DISABLED,
      EPKI_ERROR,          // EPKI refers to External PKI errors, i.e. errors in accessing external
      EPKI_INVALID_ALIAS,  //    certificates or keys.

      N_TYPES
    };

    enum {
      ERROR_START=AUTH_FAILED, // start of error events
    };

    inline const char *event_name(const Type type)
    {
      static const char *names[] = {
	"DISCONNECTED",
	"CONNECTED",
	"RECONNECTING",
	"RESOLVE",
	"WAIT",
	"WAIT_PROXY",
	"CONNECTING",
	"GET_CONFIG",
	"ASSIGN_IP",
	"ADD_ROUTES",
	"PAUSE",
	"RESUME",
	"AUTH_FAILED",
	"CERT_VERIFY_FAIL",
	"TLS_VERSION_MIN",
	"CLIENT_HALT",
	"CLIENT_RESTART",
	"CONNECTION_TIMEOUT",
	"INACTIVE_TIMEOUT",
	"DYNAMIC_CHALLENGE",
	"PROXY_NEED_CREDS",
	"PROXY_ERROR",
	"TUN_SETUP_FAILED",
	"TUN_IFACE_CREATE",
	"TUN_IFACE_DISABLED",
	"EPKI_ERROR",
	"EPKI_INVALID_ALIAS",
      };

      if (type < N_TYPES)
	return names[type];
      else
	return "UNKNOWN_EVENT_TYPE";
    }

    struct Connected;

    // The base class for all events.
    class Base : public RC<thread_safe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Base> Ptr;
      Base(Type id) : id_(id) {}

      Type id() const { return id_; }

      const char *name() const
      {
	return event_name(id_);
      }

      bool is_error() const
      {
	return int(id_) >= ERROR_START;
      }

      virtual std::string render() const
      {
	return "";
      }

      const Connected* connected_cast() const
      {
	if (id_ == CONNECTED)
	  return (const Connected*)this;
	else
	  return NULL;
      }

    private:
      Type id_;
    };

    // Specific client events.  Some events have no additional data attached to them,
    // while other events (such as Connected) have many additional data fields.

    struct Resolve : public Base
    {
      Resolve() : Base(RESOLVE) {}
    };

    struct Wait : public Base
    {
      Wait() : Base(WAIT) {}
    };

    struct WaitProxy : public Base
    {
      WaitProxy() : Base(WAIT_PROXY) {}
    };

    struct Connecting : public Base
    {
      Connecting() : Base(CONNECTING) {}
    };

    struct Reconnecting : public Base
    {
      Reconnecting() : Base(RECONNECTING) {}
    };

    struct GetConfig : public Base
    {
      GetConfig() : Base(GET_CONFIG) {}
    };

    struct AssignIP : public Base
    {
      AssignIP() : Base(ASSIGN_IP) {}
    };

    struct AddRoutes : public Base
    {
      AddRoutes() : Base(ADD_ROUTES) {}
    };

    struct Resume : public Base
    {
      Resume() : Base(RESUME) {}
    };

    struct Disconnected : public Base
    {
      Disconnected() : Base(DISCONNECTED) {}
    };

    struct ConnectionTimeout : public Base
    {
      ConnectionTimeout() : Base(CONNECTION_TIMEOUT) {}
    };

    struct InactiveTimeout : public Base
    {
      InactiveTimeout() : Base(INACTIVE_TIMEOUT) {}
    };

    struct TLSVersionMinFail : public Base
    {
      TLSVersionMinFail() : Base(TLS_VERSION_MIN) {}
    };

    struct Connected : public Base
    {
      typedef boost::intrusive_ptr<Connected> Ptr;

      Connected() : Base(CONNECTED) {}

      std::string user;
      std::string server_host;
      std::string server_port;
      std::string server_proto;
      std::string server_ip;
      std::string vpn_ip4;
      std::string vpn_ip6;
      std::string client_ip;
      std::string tun_name;

      virtual std::string render() const
      {
	std::ostringstream out;
	// eg. "godot@foo.bar.gov:443 (1.2.3.4) via TCPv4 on tun0/5.5.1.1"
	out << user << '@' << server_host << ':' << server_port
	    << " (" << server_ip << ") via " << client_ip << '/' << server_proto
	    << " on " << tun_name << '/' << vpn_ip4 << '/' << vpn_ip6;
	return out.str();
      }
    };

    struct ReasonBase : public Base {
      ReasonBase(const Type id, const std::string& reason_arg)
	: Base(id),
	  reason(reason_arg)
      {
      }

      virtual std::string render() const
      {
	return reason;
      }

      std::string reason;
    };

    struct AuthFailed : public ReasonBase
    {
      AuthFailed(const std::string& reason) : ReasonBase(AUTH_FAILED, reason) {}
    };

    struct CertVerifyFail : public ReasonBase
    {
      CertVerifyFail(const std::string& reason) : ReasonBase(CERT_VERIFY_FAIL, reason) {}
    };

    struct ClientHalt : public ReasonBase
    {
      ClientHalt(const std::string& reason) : ReasonBase(CLIENT_HALT, reason) {}
    };

    struct ClientRestart : public ReasonBase
    {
      ClientRestart(const std::string& reason) : ReasonBase(CLIENT_RESTART, reason) {}
    };

    struct DynamicChallenge : public ReasonBase
    {
      DynamicChallenge(const std::string& reason) : ReasonBase(DYNAMIC_CHALLENGE, reason) {}
    };

    struct Pause : public ReasonBase
    {
      Pause(const std::string& reason) : ReasonBase(PAUSE, reason) {}
    };

    struct ProxyError : public ReasonBase
    {
      ProxyError(const std::string& reason) : ReasonBase(PROXY_ERROR, reason) {}
    };

    struct ProxyNeedCreds : public ReasonBase
    {
      ProxyNeedCreds(const std::string& reason) : ReasonBase(PROXY_NEED_CREDS, reason) {}
    };

    struct TunSetupFailed : public ReasonBase
    {
      TunSetupFailed(const std::string& reason) : ReasonBase(TUN_SETUP_FAILED, reason) {}
    };

    struct TunIfaceCreate : public ReasonBase
    {
      TunIfaceCreate(const std::string& reason) : ReasonBase(TUN_IFACE_CREATE, reason) {}
    };

    struct TunIfaceDisabled : public ReasonBase
    {
      TunIfaceDisabled(const std::string& reason) : ReasonBase(TUN_IFACE_DISABLED, reason) {}
    };

    struct EpkiError : public ReasonBase
    {
      EpkiError(const std::string& reason) : ReasonBase(EPKI_ERROR, reason) {}
    };

    struct EpkiInvalidAlias : public ReasonBase
    {
      EpkiInvalidAlias(const std::string& reason) : ReasonBase(EPKI_INVALID_ALIAS, reason) {}
    };

    class Queue : public RC<thread_safe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Queue> Ptr;

      virtual void add_event(const Base::Ptr& event) = 0;
    };
  }
}

#endif // OPENVPN_CLIENT_CLIEVENT_H
