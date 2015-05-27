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

#ifndef OPENVPN_COMMON_REDIR_H
#define OPENVPN_COMMON_REDIR_H

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <string>
#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/tempfile.hpp>

namespace openvpn {

  struct RedirectBase
  {
    OPENVPN_EXCEPTION(redirect_std_err);
    virtual void redirect() = 0;
    virtual void close() = 0;
    virtual ~RedirectBase() {}
  };

  class RedirectStdFD : public RedirectBase
  {
  public:
    virtual void redirect() noexcept override
    {
      // stdin
      if (in.defined())
	{
	  dup2(in(), 0);
	  if (in() <= 2)
	    in.release();
	}

      // stdout
      if (out.defined())
	{
	  dup2(out(), 1);
	  if (!err.defined() && combine_out_err)
	    dup2(out(), 2);
	  if (out() <= 2)
	    out.release();
	}

      // stderr
      if (err.defined())
	{
	  dup2(err(), 2);
	  if (err() <= 2)
	    err.release();
	}

      close();
    }

    virtual void close() override
    {
      in.close();
      out.close();
      err.close();
    }

  protected:
    RedirectStdFD()
      : combine_out_err(false)
    {}

    ScopedFD in;
    ScopedFD out;
    ScopedFD err;
    bool combine_out_err;
  };

  class RedirectStd : public RedirectStdFD
  {
  public:
    // flags shortcuts
    static constexpr int FLAGS_OVERWRITE = O_CREAT | O_WRONLY | O_TRUNC;
    static constexpr int FLAGS_APPEND = O_CREAT | O_WRONLY | O_APPEND;
    static constexpr int FLAGS_MUST_NOT_EXIST = O_CREAT | O_WRONLY | O_EXCL;

    // mode shortcuts
    static constexpr mode_t MODE_ALL = 0777;
    static constexpr mode_t MODE_USER_GROUP = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    static constexpr mode_t MODE_USER = S_IRUSR | S_IWUSR;

    RedirectStd(const std::string& in_fn,
		const std::string& out_fn,
		const int out_flags = FLAGS_OVERWRITE,
		const mode_t out_mode = MODE_ALL,
		const bool combine_out_err_arg = true)
    {
      open_input(in_fn);
      open_output(out_fn, out_flags, out_mode);
      combine_out_err = combine_out_err_arg;
    }

  protected:
    RedirectStd() {}

    void open_input(const std::string& fn)
    {
      // open input file for stdin
      in.reset(open(fn.c_str(), O_RDONLY, 0));
      if (!in.defined())
	{
	  const int eno = errno;
	  OPENVPN_THROW(redirect_std_err, "error opening input file: " << fn << " : " << std::strerror(eno));
	}
    }

    void open_output(const std::string& fn,
		     const int flags,
		     const mode_t mode)
    {
      // open output file for stdout/stderr
      out.reset(open(fn.c_str(),
		     flags,
		     mode));
      if (!out.defined())
	{
	  const int eno = errno;
	  OPENVPN_THROW(redirect_std_err, "error opening output file: " << fn << " : " << std::strerror(eno));
	}
    }
  };

  class RedirectTemp : public RedirectStd
  {
  public:
    RedirectTemp(const std::string& stdin_fn,
		 TempFile& stdout_temp,
		 const bool combine_out_err_arg)
    {
      open_input(stdin_fn);
      out = std::move(stdout_temp.fd);
      combine_out_err = combine_out_err_arg;
    }
  };
}

#endif
