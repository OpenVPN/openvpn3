//
//  path.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PATH_H
#define OPENVPN_COMMON_PATH_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/platform.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace path {

#if defined(OPENVPN_PLATFORM_WIN) || defined(OPENVPN_PATH_SIMULATE_WINDOWS)
    const char dirsep[] = "\\/";
#else
    const char dirsep[] = "/";
#endif

    // true if char is a directory separator
    inline bool is_dirsep(const char c)
    {
      for (const char *p = dirsep; *p != '\0'; ++p)
	if (c == *p)
	  return true;
      return false;
    }

    inline bool win_dev(const std::string& path, const bool fully_qualified)
    {
#if defined(OPENVPN_PLATFORM_WIN) || defined(OPENVPN_PATH_SIMULATE_WINDOWS)
      // Identify usage such as "c:\\".
      return path.length() >= 3
	&& ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
	&& path[1] == ':'
	&& (!fully_qualified || is_dirsep(path[2]));
#else
      return false;
#endif
    }

    // true if path is fully qualified
    inline bool is_fully_qualified(const std::string& path)
    {
      return win_dev(path, true) || (path.length() > 0 && is_dirsep(path[0]));
    }

    // does path refer to regular file without directory traversal
    inline bool is_flat(const std::string& path)
    {
      return path.length() > 0
	&& path != "."
	&& path != ".."
	&& path.find_first_of(dirsep) == std::string::npos
	&& !win_dev(path, false);
    }

    inline std::string basename(const std::string& path)
    {
      const size_t pos = path.find_last_of(dirsep);
      if (pos != std::string::npos)
	{
	  const size_t p = pos + 1;
	  if (p >= path.length())
	    return "";
	  else
	    return path.substr(p);
	}
      else
	return path;
    }

    inline std::string dirname(const std::string& path)
    {
      const size_t pos = path.find_last_of(dirsep);
      if (pos != std::string::npos)
	{
	  if (pos == 0)
	    return "/";
	  else
	    return path.substr(0, pos);
	}
      else
	return "";
    }

    inline std::string ext(const std::string& basename)
    {
      const size_t pos = basename.find_last_of('.');
      if (pos != std::string::npos)
	{
	  const size_t p = pos + 1;
	  if (p >= basename.length())
	    return "";
	  else
	    return basename.substr(p);
	}
      else
	return "";
    }

    inline std::string join(const std::string& p1, const std::string& p2)
    {
      if (p1.empty() || is_fully_qualified(p2))
	return p2;
      else
	return string::add_trailing(p1, dirsep[0]) + p2;
    }

  } // namespace path
} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
