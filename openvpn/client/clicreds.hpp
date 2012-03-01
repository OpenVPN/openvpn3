#ifndef OPENVPN_CLIENT_CLICREDS_H
#define OPENVPN_CLIENT_CLICREDS_H

#include <string>
#include <sstream>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/base64.hpp>

namespace openvpn {

  class ClientCreds : public RC<thread_safe_refcount> {
  public:
    typedef boost::intrusive_ptr<ClientCreds> Ptr;

    ClientCreds() : replace_password_with_session_id(false) {}

    void set_base64(const Base64::Ptr& b64_arg) { b64 = b64_arg; }
    void set_username(const std::string& username_arg) { username = username_arg; }
    void set_password(const std::string& password_arg) { password = password_arg; }
    void set_response(const std::string& response_arg) { response = response_arg; }
    void set_replace_password_with_session_id(const bool value) { replace_password_with_session_id = value; };

    const std::string& get_username() const { return username; }

    std::string get_password() const
    {
      if (!response.empty() && b64)
	{
	  // SCRV1:<BASE64_PASSWORD>:<BASE64_RESPONSE>
	  std::ostringstream os;
	  os << "SCRV1:" << b64->encode(password) << ':' << b64->encode(response);
	  return os.str();
	}
      else
	return password;
    }

    void set_session_id(const std::string& sess_id)
    {
      if (replace_password_with_session_id)
	{
	  password = sess_id;
	  response = "";
	}
    }

  private:
    std::string username;
    std::string password;

    // response to challenge
    std::string response;

    // If true, on successful connect, we will replace the password
    // with the session ID we receive from the server.
    bool replace_password_with_session_id;

    // Used for challenge/response encoding
    Base64::Ptr b64;
  };

}

#endif
