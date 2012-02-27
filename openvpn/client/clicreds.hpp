#ifndef OPENVPN_CLIENT_CLICREDS_H
#define OPENVPN_CLIENT_CLICREDS_H

#include <string>

#include <openvpn/common/rc.hpp>

namespace openvpn {

  class ClientCreds : public RC<thread_safe_refcount> {
  public:
    typedef boost::intrusive_ptr<ClientCreds> Ptr;

    ClientCreds() : replace_password_with_session_id(false) {}

    std::string username;
    std::string password;

    // response to static challenge
    std::string static_response;

    // If true, on successful connect, we will replace the password
    // with the session ID we receive from the server.
    bool replace_password_with_session_id;
  };

}

#endif
