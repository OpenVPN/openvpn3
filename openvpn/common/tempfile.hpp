//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_COMMON_TEMPFILE_H
#define OPENVPN_COMMON_TEMPFILE_H

#include <stdlib.h>
#include <errno.h>
#include <cstring>     // for memcpy
#include <unistd.h>    // for write, unlink

#include <string>
#include <memory>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/write.hpp>

namespace openvpn {
  class TempFile
  {
  public:
    OPENVPN_EXCEPTION(tempfile_exception);

    TempFile(const std::string& fn_template,
	     const bool fn_delete)
      : fn(new char[fn_template.length()+1]),
	del(fn_delete)
    {
      std::memcpy(fn.get(), fn_template.c_str(), fn_template.length()+1);
      const size_t pos = fn_template.find("XXXXXX");
      if (pos != std::string::npos)
	{
	  const int suffixlen = fn_template.length() - pos - 6;
	  if (suffixlen > 0)
	    fd.reset(::mkstemps(fn.get(), suffixlen));
	  else
	    fd.reset(::mkstemp(fn.get()));
	  if (!fd.defined())
	    {
	      const int eno = errno;
	      OPENVPN_THROW(tempfile_exception, "error creating temporary file from template: " << fn_template << " : " << std::strerror(eno));
	    }
	}
      else
	OPENVPN_THROW(tempfile_exception, "badly formed temporary file template: " << fn_template);
    }

    ~TempFile()
    {
      fd.close();
      delete_file();
    }

    void write(const std::string& content)
    {
      const ssize_t size = write_retry(fd(), content.c_str(), content.length());
      if (size < 0)
	{
	  const int eno = errno;
	  OPENVPN_THROW(tempfile_exception, "error writing to temporary file: " << filename() << " : " << std::strerror(eno));
	}
      else if (size != content.length())
	{
	  OPENVPN_THROW(tempfile_exception, "incomplete write to temporary file: " << filename());
	}
    }

    std::string filename() const
    {
      if (fn)
	return fn.get();
      else
	return "";
    }

    void close_file()
    {
      if (!fd.close())
	{
	  const int eno = errno;
	  OPENVPN_THROW(tempfile_exception, "error closing temporary file: " << filename() << " : " << std::strerror(eno));
	}
    }

    void delete_file()
    {
      if (fn && del)
	{
	  ::unlink(fn.get());
	  del = false;
	}
    }

    ScopedFD fd;

  private:
    std::unique_ptr<char[]> fn;
    bool del;
  };
}

#endif
