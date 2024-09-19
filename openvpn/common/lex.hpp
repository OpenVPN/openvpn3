//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// A set of lexical analyzer classes.  These classes can be combined
// with the methods in split.hpp to create parsers.

#pragma once

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
    void put(char c)
    {
        in_backslash_ = false;
        if (backslash_)
        {
            ch = c;
            backslash_ = false;
            in_backslash_ = true;
        }
        else if (c == '\\')
        {
            backslash_ = true;
            ch = -1;
        }
        else if (c == '\"')
        {
            in_quote_ = !in_quote_;
            ch = -1;
        }
        else
            ch = c;
    }

    bool available() const
    {
        return ch != -1;
    }
    int get() const
    {
        return ch;
    }
    void reset()
    {
        ch = -1;
    }

    bool in_quote() const
    {
        return in_quote_;
    }
    bool in_backslash() const
    {
        return in_backslash_;
    }

  private:
    bool in_quote_ = false;
    bool backslash_ = false;
    bool in_backslash_ = false;
    int ch = -1;
};

// A null lexical analyzer has no special understanding
// of any particular string character.
class NullLex
{
  public:
    void put(char c)
    {
        ch = c;
    }
    bool available() const
    {
        return ch != -1;
    }
    int get() const
    {
        return ch;
    }
    void reset()
    {
        ch = -1;
    }
    bool in_quote() const
    {
        return false;
    }
    bool in_backslash() const
    {
        return false;
    }

  private:
    int ch = -1;
};

} // namespace openvpn
