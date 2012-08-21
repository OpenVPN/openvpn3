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

    ClientCreds() : replace_password_with_session_id(false),
		    did_replace_password_with_session_id(false) {}

    void set_username(const std::string& username_arg)
    {
      username = username_arg;
    }

    void set_password(const std::string& password_arg)
    {
      password = password_arg;
      did_replace_password_with_session_id = false;
    }

    void set_response(const std::string& response_arg)
    {
      response = response_arg;
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
	  if (dynamic_challenge)
	    {
	      username = dynamic_challenge->get_username();
	      dynamic_challenge.reset();
	    }
	  did_replace_password_with_session_id = true;
	}
    }

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

    bool username_defined() const
    {
      return !username.empty();
    }

    bool password_defined() const
    {
      return !password.empty();
    }

    bool session_id_defined() const
    {
      return did_replace_password_with_session_id;
    }

  private:
    // Standard credentials
    std::string username;
    std::string password;

    // Response to challenge
    std::string response;

    // Info describing a dynamic challenge
    ChallengeResponse::Ptr dynamic_challenge;

    // If true, on successful connect, we will replace the password
    // with the session ID we receive from the server.
    bool replace_password_with_session_id;

    // true if password has been replaced with Session ID
    bool did_replace_password_with_session_id;
  };

}

#endif
