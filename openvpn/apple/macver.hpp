//
//  macver.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLE_MACVER_H
#define OPENVPN_APPLE_MACVER_H

#include <errno.h>
#include <sys/sysctl.h>

#include <string>
#include <sstream>
#include <vector>

#include <openvpn/common/split.hpp>
#include <openvpn/common/number.hpp>

namespace openvpn {
  namespace Mac {
    class Version
    {
    public:
      // Mac OS X versions
      // 13.x.x  OS X 10.9.x Mavericks
      // 12.x.x  OS X 10.8.x Mountain Lion
      // 11.x.x  OS X 10.7.x Lion
      // 10.x.x  OS X 10.6.x Snow Leopard
      //  9.x.x  OS X 10.5.x Leopard
      //  8.x.x  OS X 10.4.x Tiger
      //  7.x.x  OS X 10.3.x Panther
      //  6.x.x  OS X 10.2.x Jaguar
      //  5.x    OS X 10.1.x Puma

      enum {
	OSX_10_9=13,
	OSX_10_8=12,
	OSX_10_7=11,
	OSX_10_6=10,
      };

      Version()
      {
	typedef std::vector<std::string> StringList;
	ver[0] = ver[1] = ver[2] = -1;
	char str[256];
	size_t size = sizeof(str);
	int ret = sysctlbyname("kern.osrelease", str, &size, NULL, 0);
	if (!ret)
	  {
	    std::string verstr = std::string(str, size);
	    StringList sl;
	    sl.reserve(3);
	    Split::by_char_void<StringList, NullLex, Split::NullLimit>(sl, verstr, '.');
	    for (size_t i = 0; i < 3; ++i)
	      {
		if (i < sl.size())
		  parse_number(sl[i], ver[i]);
	      }
	  }
      }

      int major() const { return ver[0]; }
      int minor() const { return ver[1]; }
      int build() const { return ver[2]; }

      std::string to_string() const
      {
	std::ostringstream os;
	os << major() << '.' << minor() << '.' << build();
	return os.str();
      }

    private:
      int ver[3];
    };
  }
}

#endif
