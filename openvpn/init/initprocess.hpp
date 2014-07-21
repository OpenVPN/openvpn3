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

// Process-wide static initialization

#ifndef OPENVPN_INIT_INITPROCESS_H
#define OPENVPN_INIT_INITPROCESS_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/compress/compress.hpp>
#include <openvpn/init/cryptoinit.hpp>
#include <openvpn/init/engineinit.hpp>

namespace openvpn {
  namespace InitProcess {

    class Init
    {
    public:
      Init()
      {
	// initialize time base
	Time::reset_base();

	// initialize compression
	CompressContext::init_static();

	// init crypto acceleration (if available)
	setup_crypto_engine("auto");

	base64_init_static();
      }

      ~Init()
      {
	base64_uninit_static();
      }

    private:
      // initialize SSL library
      crypto_init crypto_init_;
    };

    // process-wide singular instance
    Init* the_instance; // GLOBAL
    Mutex the_instance_mutex; // GLOBAL

    inline void init()
    {
      Mutex::scoped_lock lock(the_instance_mutex);
      if (!the_instance)
	the_instance = new Init();
    }

    inline void uninit()
    {
      Mutex::scoped_lock lock(the_instance_mutex);
      if (the_instance)
	{
	  delete the_instance;
	  the_instance = NULL;
	}
    }

  }
}

#endif
