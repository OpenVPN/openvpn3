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

#ifndef OPENVPN_COMMON_FORMAT_H
#define OPENVPN_COMMON_FORMAT_H

#include <cstddef> // for std::nullptr_t
#include <string>
#include <sstream>
#include <ostream>
#include <type_traits>
#include <utility>

namespace openvpn {

  // Convert an arbitrary argument to a string.

  // numeric types
  template <typename T,
	    typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
  inline std::string to_string(T value)
  {
    return std::to_string(value);
  }

  // non-numeric types not specialized below
  template <typename T,
	    typename std::enable_if<!std::is_arithmetic<T>::value, int>::type = 0>
  inline std::string to_string(const T& value)
  {
    std::ostringstream os;
    os << value;
    return os.str();
  }

  // specialization for std::string
  inline std::string to_string(const std::string& value)
  {
    return value;
  }

  // specialization for char *
  inline std::string to_string(const char *value)
  {
    return std::string(value);
  }

  // specialization for char
  inline std::string to_string(const char c)
  {
    return std::string(&c, 1);
  }

  // specialization for nullptr
  inline std::string to_string(std::nullptr_t)
  {
    return "nullptr";
  }

  // Concatenate arguments into a string:
  // print(args...)   -- concatenate
  // prints(args...)  -- concatenate but delimit args with space
  // printd(char delim, args...) -- concatenate but delimit args with delim
  namespace print_detail {
    template<typename T>
    inline void print(std::ostream& os, char delim, const T& first)
    {
      os << first;
    }

    template<typename T, typename... Args>
    inline void print(std::ostream& os, char delim, const T& first, Args... args)
    {
      os << first;
      if (delim)
	os << delim;
      print(os, delim, args...);
    }
  }

  template<typename... Args>
  inline std::string printd(char delim, Args... args)
  {
    std::ostringstream os;
    print_detail::print(os, delim, args...);
    return os.str();
  }

  template<typename... Args>
  inline std::string print(Args... args)
  {
    return printd(0, args...);
  }

  template<typename... Args>
  inline std::string prints(Args... args)
  {
    return printd(' ', args...);
  }

  // String formatting similar to sprintf.
  // %s formats any argument regardless of type.
  // %r formats any argument regardless of type and quotes it.
  // %% formats '%'
  // printfmt(<format_string>, args...)
  class PrintFormatted
  {
  public:
    PrintFormatted(const std::string& fmt_arg, const size_t reserve)
      : fmt(fmt_arg),
	fi(fmt.begin()),
	pct(false)
    {
      out.reserve(reserve);
    }

    void process()
    {
      process_finish();
    }

    template<typename T>
    void process(const T& last)
    {
      process_arg(last);
      process_finish();
    }

    template<typename T, typename... Args>
    void process(const T& first, Args... args)
    {
      process_arg(first);
      process(args...);
    }

    std::string str()
    {
      return std::move(out);
    }

  private:
    PrintFormatted(const PrintFormatted&) = delete;
    PrintFormatted& operator=(const PrintFormatted&) = delete;

    template<typename T>
    bool process_arg(const T& arg)
    {
      while (fi != fmt.end())
	{
	  const char c = *fi++;
	  if (pct)
	    {
	      pct = false;
	      if (c == 's')
		{
		  append_string(out, arg);
		  return true;
		}
	      else if (c == 'r')
		{
		  append_string(out, '\"');
		  append_string(out, arg);
		  append_string(out, '\"');
		  return true;
		}
	      else
		out += c;
	    }
	  else
	    {
	      if (c == '%')
		pct = true;
	      else
		out += c;
	    }
	}
      return false;
    }

    void process_finish()
    {
      // '?' printed for %s operators that don't match an argument
      while (process_arg("?"))
	;
    }

    // numeric types
    template <typename T,
	      typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
    inline void append_string(std::string& str, T value)
    {
      str += std::to_string(value);
    }

    // non-numeric types not specialized below
    template <typename T,
	      typename std::enable_if<!std::is_arithmetic<T>::value, int>::type = 0>
    inline void append_string(std::string& str, const T& value)
    {
      std::ostringstream os;
      os << value;
      str += os.str();
    }

    // specialization for std::string
    inline void append_string(std::string& str, const std::string& value)
    {
      str += value;
    }

    // specialization for char *
    inline void append_string(std::string& str, const char *value)
    {
      str += value;
    }

    // specialization for char
    inline void append_string(std::string& str, const char c)
    {
      str += c;
    }

    // specialization for nullptr
    inline void append_string(std::string& str, std::nullptr_t)
    {
      str += "nullptr";
    }

    const std::string& fmt;
    std::string::const_iterator fi;
    std::string out;
    bool pct;
  };

  template<typename... Args>
  inline std::string printfmt(const std::string& fmt, Args... args)
  {
    PrintFormatted pf(fmt, 256);
    pf.process(args...);
    return pf.str();
  }

} // namespace openvpn

#endif
