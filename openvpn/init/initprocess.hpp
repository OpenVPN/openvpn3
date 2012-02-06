#ifndef OPENVPN_COMMON_INITPROCESS_H
#define OPENVPN_COMMON_INITPROCESS_H

#include <openvpn/common/types.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/compress/compress.hpp>
#include <openvpn/gencrypto/cryptoinit.hpp>

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
      }

    private:
      // initialize SSL library
      crypto_init crypto_init_;
    };

    // process-wide singular instance
    Init* the_instance;

    inline void init()
    {
      if (!the_instance)
	the_instance = new Init();
    }

    inline void uninit()
    {
      if (the_instance)
	{
	  delete the_instance;
	  the_instance = NULL;
	}
    }
  }
}

#endif
