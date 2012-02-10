#ifndef OPENVPN_INIT_INITPROCESS_H
#define OPENVPN_INIT_INITPROCESS_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/compress/compress.hpp>
#include <openvpn/gencrypto/cryptoinit.hpp>
#include <openvpn/gencrypto/genengine.hpp>

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

	// initialize crypto engines if available
	setup_crypto_engine("auto");
      }

    private:
      // initialize SSL library
      crypto_init crypto_init_;
    };

    // process-wide singular instance
    Init* volatile the_instance;
    Mutex the_instance_mutex;

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
