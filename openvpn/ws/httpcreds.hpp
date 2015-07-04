//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_WS_CREDS_H
#define OPENVPN_WS_CREDS_H

#include <string>
#include <vector>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/memneq.hpp>
#include <openvpn/common/umask.hpp>
#include <openvpn/common/unicode.hpp>
#include <openvpn/http/header.hpp>

namespace openvpn {
  namespace WS {
    struct Creds
    {
      OPENVPN_EXCEPTION(web_creds_error);

      static Creds load_from_header(const HTTP::HeaderList& headlist,
				    const bool password_required,
				    const bool throw_on_error)
      {
	Creds ret;
	try
	  {
	    // Authorization: Basic Zm9vOmJhcg==
	    for (auto &h : headlist)
	      {
		if (string::strcasecmp(h.name, "authorization") == 0
		    && h.value.length() >= 7
		    && string::strcasecmp(h.value.substr(0, 6), "basic ") == 0)
		  {
		    const std::string creds = base64->decode(h.value.substr(6));
		    const auto cv = Split::by_char<std::vector<std::string>, NullLex, Split::NullLimit>(creds, ':', 0, 1);
		    if (cv.size() != 2)
		      throw Exception("error splitting credentials");
		    if (!Unicode::is_valid_utf8(cv[0]))
		      throw Exception("username not UTF-8");
		    if (!Unicode::is_valid_utf8(cv[1]))
		      throw Exception("password not UTF-8");
		    if (cv[0].empty())
		      throw Exception("username empty");
		    if (password_required && cv[1].empty())
		      throw Exception("password empty");
		    ret.username = cv[0];
		    ret.password = cv[1];
		    break;
		  }
	      }
	  }
	catch (const std::exception& e)
	  {
	    if (throw_on_error)
	      throw web_creds_error(e.what());
	  }
	return ret;
      }

      static Creds load_from_file(const std::string& fn,
				  const bool password_required,
				  const bool throw_on_error)
      {
	Creds ret;
	try
	  {
	    const std::string content = read_text_utf8(fn);
	    SplitLines sl(content, 1024);
	    std::string u, p;
	    if (sl.next(u) != SplitLines::S_OK)
	      throw Exception(fn + " : username missing");
	    if (sl.next(p) != SplitLines::S_OK)
	      throw Exception(fn + " : password missing");
	    if (u.empty())
	      throw Exception(fn + " : username empty");
	    if (password_required && p.empty())
	      throw Exception(fn + " : password empty");
	    ret.username = std::move(u);
	    ret.password = std::move(p);
	  }
	catch (const std::exception& e)
	  {
	    if (throw_on_error)
	      throw web_creds_error(e.what());
	  }
	return ret;
      }

      bool defined() const
      {
	return !username.empty();
      }

      bool defined_full() const
      {
	return !username.empty() && !password.empty();
      }

      void save_to_file(const std::string& fn) const
      {
	const UMaskPrivate um;
	write_string(fn, username + '\n' + password + '\n');
      }

      bool operator==(const Creds& rhs) const
      {
	if (username != rhs.username)
	  return false;
	if (password.length() != rhs.password.length())
	  return false;
	if (crypto::memneq(password.c_str(), rhs.password.c_str(), password.length()))
	  return false;
	return true;
      }

      bool operator!=(const Creds& rhs) const
      {
	return !operator==(rhs);
      }

      std::string to_string() const
      {
	return username + '/' + password;
      }

      std::string username;
      std::string password;
    };
  }
}

#endif
