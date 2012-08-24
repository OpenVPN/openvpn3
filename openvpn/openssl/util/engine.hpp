//
//  engine.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPENSSL_UTIL_ENGINE_H
#define OPENVPN_OPENSSL_UTIL_ENGINE_H

#include <string>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openvpn/common/exception.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(openssl_engine_error);

  void openssl_setup_engine (const std::string& engine)
  {
#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines ();

    if (engine == "auto")
      {
	ENGINE_register_all_complete ();
	return;
      }

    ENGINE *e = ENGINE_by_id (engine.c_str());
    if (!e)
      throw openssl_engine_error();
    if (!ENGINE_set_default (e, ENGINE_METHOD_ALL))
      throw openssl_engine_error();
#endif
  }

} // namespace openvpn

#endif // OPENVPN_OPENSSL_UTIL_ENGINE_H
