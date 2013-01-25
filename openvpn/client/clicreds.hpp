//
//  clicreds.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// This class encapsulates the state of authentication credentials
// maintained by an OpenVPN client.  It understands dynamic
// challenge/response cookies, and Session Token IDs (where the
// password in the object is wiped and replaced by a token used
// for further authentications).

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

    ClientCreds() : allow_cache_password(false),
		    password_save_defined(false),
		    replace_password_with_session_id(false),
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

    void set_replace_password_with_session_id(const bool value)
    {
      replace_password_with_session_id = value;
    }

    void enable_password_cache(const bool value)
    {
      allow_cache_password = value;
    }

    bool get_replace_password_with_session_id() const
    {
      return replace_password_with_session_id;
    }

    void set_session_id(const std::string& sess_id)
    {
      // force Session ID use if dynamic challenge is enabled
      if (dynamic_challenge && !replace_password_with_session_id)
	replace_password_with_session_id = true;

      if (replace_password_with_session_id)
	{
	  if (allow_cache_password && !password_save_defined)
	    {
	      password_save = password;
	      password_save_defined = true;
	    }
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

    bool can_retry_auth_with_cached_password()
    {
      if (password_save_defined)
	{
	  password = password_save;
	  password_save = "";
	  password_save_defined = false;
	  return true;
	}
      else
	return false;
    }

  private:
    // Standard credentials
    std::string username;
    std::string password;

    // Password caching
    bool allow_cache_password;
    bool password_save_defined;
    std::string password_save;

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
