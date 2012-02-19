#ifndef OPENVPN_CLIENT_CLIEVENT_H
#define OPENVPN_CLIENT_CLIEVENT_H

#include <sstream>
#include <deque>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/transport/protocol.hpp>

namespace openvpn {
  namespace ClientEvent {
    enum Type {
      DISCONNECTED=0,
      CONNECTED,
      RECONNECTING,
      NEED_AUTH,
      RESOLVE,
      WAIT,
      CONNECTING,
      GET_CONFIG,
      ASSIGN_IP,
      ADD_ROUTES,
      AUTH_FAILED,
      TUN_SETUP_FAILED,
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
	"NEED_AUTH",
	"RESOLVE",
	"WAIT",
	"CONNECTING",
	"GET_CONFIG",
	"ASSIGN_IP",
	"ADD_ROUTES",
	"AUTH_FAILED",
	"TUN_SETUP_FAILED",
      };

      if (type < N_TYPES)
	return names[type];
      else
	return "UNKNOWN_EVENT_TYPE";
    }

    class Base : public RC<thread_unsafe_refcount>
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
	return name();
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

    struct Disconnected : public Base
    {
      Disconnected() : Base(DISCONNECTED) {}
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
      std::string vpn_ip;
      std::string tun_name;

      virtual std::string render() const
      {
	std::ostringstream out;
	// eg. "CONNECTED godot@foo.bar.gov:443 (1.2.3.4) via TCPv4 on tun0/5.5.1.1"
	out << "CONNECTED " << user << '@' << server_host << ':' << server_port
	    << " (" << server_ip << ") via " << server_proto
	    << " on " << tun_name << '/' << vpn_ip;
	return out.str();
      }
    };

    struct AuthFailed : public Base
    {
      AuthFailed(const std::string& reason_arg)
	: Base(AUTH_FAILED),
	  reason(reason_arg)
      {
      }

      virtual std::string render() const
      {
	std::ostringstream out;
	if (!reason.empty())
	  out << "AUTH_FAILED: " << reason;
	else
	  out << "AUTH_FAILED";
	return out.str();
      }

      std::string reason;
    };

    struct TunSetupFailed : public Base
    {
      TunSetupFailed(const std::string& reason_arg)
	: Base(TUN_SETUP_FAILED),
	  reason(reason_arg)
      {
      }

      virtual std::string render() const
      {
	std::ostringstream out;
	if (!reason.empty())
	  out << "TUN_SETUP_FAILED: " << reason;
	else
	  out << "TUN_SETUP_FAILED";
	return out.str();
      }

      std::string reason;
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
