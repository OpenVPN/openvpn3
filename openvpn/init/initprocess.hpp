//
//  initprocess.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
