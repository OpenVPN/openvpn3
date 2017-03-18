//
//  writeprivate.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_COMMON_WRITEPRIVATE_H
#define OPENVPN_COMMON_WRITEPRIVATE_H

#include <string>

#include <openvpn/common/platform.hpp>

#if !defined(OPENVPN_PLATFORM_WIN)
#include <cstring>     // for std::strerror()
#include <sys/types.h> // for open(), ftruncate()
#include <sys/stat.h>  // for open()
#include <fcntl.h>     // for open()
#include <unistd.h>    // for write(), ftruncate()
#include <errno.h>
#endif

#include <openvpn/common/exception.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/buffer/buffer.hpp>

#if !defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/write.hpp>
#endif

namespace openvpn {

#if defined(OPENVPN_PLATFORM_WIN)

  inline void write_private(const std::string& path, const void *buf, size_t count)
  {
    OPENVPN_THROW_EXCEPTION("write_private('" << path << "') : not implemented on Windows yet");
  }

#else

  inline void write_private(const std::string& path, const void *buf, size_t count)
  {
    ScopedFD fd(::open(path.c_str(), O_WRONLY|O_CREAT|O_CLOEXEC, S_IRUSR|S_IWUSR));
    if (!fd.defined())
      {
	const int eno = errno;
	OPENVPN_THROW_EXCEPTION(path << " : open error : " << std::strerror(eno));
      }
    if (::ftruncate(fd(), 0) < 0)
      {
	const int eno = errno;
	OPENVPN_THROW_EXCEPTION(path << " : truncate error : " << std::strerror(eno));
      }
    const ssize_t len = write_retry(fd(), buf, count);
    if (len == -1)
      {
	const int eno = errno;
	OPENVPN_THROW_EXCEPTION(path << " : write error : " << std::strerror(eno));
      }
    else if (len != count)
      OPENVPN_THROW_EXCEPTION(path << " : unexpected write size");
    if (!fd.close())
      {
	const int eno = errno;
	OPENVPN_THROW_EXCEPTION(path << " : close error : " << std::strerror(eno));
      }
  }

#endif

  inline void write_private(const std::string& path, const Buffer& buf)
  {
    write_private(path, buf.c_data(), buf.size());
  }

  inline void write_private(const std::string& path, const std::string& str)
  {
    write_private(path, str.c_str(), str.length());
  }

}

#endif
