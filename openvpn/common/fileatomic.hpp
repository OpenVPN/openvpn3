//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// Atomic file-handling methods.

#ifndef OPENVPN_COMMON_FILEATOMIC_H
#define OPENVPN_COMMON_FILEATOMIC_H

#include <stdio.h> // for rename()
#include <errno.h>
#include <cstring>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/random/randapi.hpp>

#if defined(OPENVPN_PLATFORM_WIN)
#error atomic file methods not supported on Windows
#endif

namespace openvpn {
  // Atomically write binary buffer to file (relies on
  // the atomicity of rename())
  inline void write_binary_atomic(const std::string& filename,
				  const Buffer& buf,
				  RandomAPI& rng)
  {
    // generate temporary filename
    unsigned char data[16];
    rng.rand_fill(data);
    const std::string tfn = filename + '.' + render_hex(data, sizeof(data));

    // write to temporary file
    write_binary(tfn, buf);

    // then move into position
    if (::rename(tfn.c_str(), filename.c_str()) == -1)
      {
	const int eno = errno;
	OPENVPN_THROW(open_file_error, "error moving '" << tfn << "' -> '" << filename << "' : " << std::strerror(eno));
      }
  }
}

#endif
