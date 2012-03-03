#ifndef OPENVPN_CLIENT_CLICREDS_H
#define OPENVPN_CLIENT_CLICREDS_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/transport/protocol.hpp>
#include <openvpn/auth/cr.hpp>

namespace openvpn {

  class ClientCreds : public RC<thread_safe_refcount> {
  public:
    typedef boost::intrusive_ptr<ClientCreds> Ptr;

    ClientCreds() : replace_password_with_session_id(false) {}

    void set_username(const std::string& username_arg) { username = username_arg; }
    void set_password(const std::string& password_arg) { password = password_arg; }
    void set_response(const std::string& response_arg) { response = response_arg; }
    void set_server_override(const std::string& server_override_arg) { server_override = server_override_arg; }

    void set_proto_override(const std::string& proto_override_arg)
    {
      if (!proto_override_arg.empty())
	proto_override = Protocol::parse(proto_override_arg);
    }

    void set_dynamic_challenge_cookie(const std::string& cookie)
    {
      if (!cookie.empty())
	dynamic_challenge.reset(new ChallengeResponse(cookie));
    }

    void set_replace_password_with_session_id(const bool value) { replace_password_with_session_id = value; };

    void set_session_id(const std::string& sess_id)
    {
      if (replace_password_with_session_id)
	{
	  password = sess_id;
	  response = "";
	  dynamic_challenge.reset();
	}
    }

    const Protocol& get_proto_override() const { return proto_override; }
    const std::string& get_server_override() const { return server_override; }

    std::string get_username() const
    {
      if (dynamic_challenge)
	return dynamic_challenge->get_username();
      else
	return username;
    }

    std::string get_password() const
    {
      if (dynamic_challenge)
	return dynamic_challenge->construct_dynamic_password(response);
      else if (response.empty())
	return password;
      else
	return ChallengeResponse::construct_static_password(password, response);
    }

  private:
    // Standard credentials
    std::string username;
    std::string password;

    // Response to challenge
    std::string response;

    // User wants to use a different server than that specified in "remote"
    // option of config file
    std::string server_override;

    // User wants to force a given transport protocol
    Protocol proto_override;

    // Info describing a dynamic challenge
    ChallengeResponse::Ptr dynamic_challenge;

    // If true, on successful connect, we will replace the password
    // with the session ID we receive from the server.
    bool replace_password_with_session_id;
  };

}

#endif
