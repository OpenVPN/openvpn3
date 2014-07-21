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

// A scoped file descriptor that is automatically closed by its destructor.

#ifndef OPENVPN_COMMON_SCOPED_FD_H
#define OPENVPN_COMMON_SCOPED_FD_H

#include <unistd.h> // for close()

#include <boost/noncopyable.hpp>

namespace openvpn {

  class ScopedFD : boost::noncopyable
  {
  public:
    typedef int base_type;

    ScopedFD() : fd(undefined()) {}

    explicit ScopedFD(const int fd_arg)
      : fd(fd_arg) {}

    static int undefined() { return -1; }

    int release()
    {
      const int ret = fd;
      fd = -1;
      //OPENVPN_LOG("**** SFD RELEASE=" << ret);
      return ret;
    }

    static bool defined_static(int fd)
    {
      return fd >= 0;
    }

    bool defined() const
    {
      return defined_static(fd);
    }

    int operator()() const
    {
      return fd;
    }

    void reset(const int fd_arg)
    {
      close();
      fd = fd_arg;
      //OPENVPN_LOG("**** SFD RESET=" << fd);
    }

    // unusual semantics: replace fd without closing it first
    void replace(const int fd_arg)
    {
      //OPENVPN_LOG("**** SFD REPLACE " << fd << " -> " << fd_arg);
      fd = fd_arg;
    }

    // return false if close error
    bool close()
    {
      if (defined())
	{
	  const int status = ::close(fd);
	  //OPENVPN_LOG("**** SFD CLOSE fd=" << fd << " status=" << status);
	  fd = -1;
	  return status == 0;
	}
      else
	return true;
    }

    ~ScopedFD()
    {
      //OPENVPN_LOG("**** SFD DESTRUCTOR");
      close();
    }

  private:
    int fd;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SCOPED_FD_H
