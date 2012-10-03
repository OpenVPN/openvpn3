//
//  clievent.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
      DISCONNECTED=0,
      CONNECTED,
      RECONNECTING,
      RESOLVE,
      WAIT,
      CONNECTING,
      GET_CONFIG,
      ASSIGN_IP,
      ADD_ROUTES,
      PAUSE,
      RESUME,

      // start of errors, must be marked by ERROR_START
      AUTH_FAILED,
      CLIENT_HALT,
      CLIENT_RESTART,
      CONNECTION_TIMEOUT,
      DYNAMIC_CHALLENGE,
      TUN_SETUP_FAILED,
      EPKI_ERROR,
      EPKI_INVALID_ALIAS,

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
	"CONNECTING",
	"GET_CONFIG",
	"ASSIGN_IP",
	"ADD_ROUTES",
	"PAUSE",
	"RESUME",
	"AUTH_FAILED",
	"CLIENT_HALT",
	"CLIENT_RESTART",
	"CONNECTION_TIMEOUT",
	"DYNAMIC_CHALLENGE",
	"TUN_SETUP_FAILED",
	"EPKI_ERROR",
	"EPKI_INVALID_ALIAS",
      };

      if (type < N_TYPES)
	return names[type];
      else
	return "UNKNOWN_EVENT_TYPE";
    }

    struct Connected;

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

    struct Resolve : public Base
    {
      Resolve() : Base(RESOLVE) {}
    };

    struct Wait : public Base
    {
      Wait() : Base(WAIT) {}
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

    struct Pause : public Base
    {
      Pause() : Base(PAUSE) {}
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

    struct TunSetupFailed : public ReasonBase
    {
      TunSetupFailed(const std::string& reason) : ReasonBase(TUN_SETUP_FAILED, reason) {}
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
