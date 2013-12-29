//
//  lex.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A set of lexical analyzer classes.  These classes can be combined
// with the methods in split.hpp to create parsers.

#ifndef OPENVPN_COMMON_LEX_H
#define OPENVPN_COMMON_LEX_H

#include <openvpn/common/string.hpp>

namespace openvpn {

  // This class (or others that define an is_space method) is used as a
  // template parameter to methods in split.hpp.
  struct SpaceMatch
  {
    static bool is_space(char c)
    {
      return string::is_space(c);
    }
  };

  // A basic lexical analyzer that understands quoting
  class StandardLex
  {
  public:
    StandardLex() : in_quote_(false), backslash(false), ch(-1) {}

    void put(char c)
    {
      if (backslash)
	{
	  ch = c;
	  backslash = false;
	}
      else if (c == '\\')
	{
	  backslash = true;
	  ch = -1;
	}
      else if (c == '\"')
	{
	  in_quote_ = !in_quote_;
	  ch = -1;
	}
      else
	{
	  ch = c;
	}
    }

    bool available() const { return ch != -1; }
    int get() const { return ch; }
    void reset() { ch = -1; }

    bool in_quote() const { return in_quote_; }

  private:
    bool in_quote_;
    bool backslash;
    int ch;
  };

  // A null lexical analyzer has no special understanding
  // of any particular string character.
  class NullLex
  {
  public:
    NullLex() : ch(-1) {}

    void put(char c) { ch = c; }
    bool available() const { return ch != -1; }
    int get() const { return ch; }
    void reset() { ch = -1; }
    bool in_quote() const { return false; }

  private:
    int ch;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_LEX_H
