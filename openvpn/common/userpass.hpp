//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
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

#ifndef OPENVPN_COMMON_USERPASS_H
#define OPENVPN_COMMON_USERPASS_H

#include <string>
#include <vector>
#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/file.hpp>

namespace openvpn {
namespace UserPass {

OPENVPN_EXCEPTION(creds_error);

enum Flags
{
    OPT_REQUIRED = (1 << 0),      //!< option must be present
    OPT_OPTIONAL = (1 << 1),      //!< if option is not present, USERNAME_REQUIRED and PASSWORD_REQUIRED are ignored
    USERNAME_REQUIRED = (1 << 2), //!< username must be present
    PASSWORD_REQUIRED = (1 << 3), //!< password must be present
    TRY_FILE = (1 << 4),          //!< option argument might be a filename, try to load creds from it
};

/**
 * @brief interpret user-pass option
 *
 * If the option is present without argument, then returns true unless
 * OPT_REQUIRED flag set. If OPT_REQUIRED flag is set, the option needs
 * to have exactly one argument.
 *
 * The argument might be specified as a multiline argument. I.e.
 * <opt_name>
 * username
 * password
 * </opt_name>
 *
 * The multiline argument is allowed to be 1024 UTF-8 characters in
 * length. If it is longer, the function will throw an exception.
 *
 * If the TRY_FILE flag is set and the argument is not multiline,
 * then it is interpreted as a filepath and the contents of the file
 * will replace the argument.
 *
 * Lines in the file are only allowed to be 1024 bytes in length.
 * Longer lines will cause an exception to be thrown.
 *
 * If the argument contains a newline, then the first line is used as the
 * username and the second line is used as the password, otherwise the argument
 * is the username. Note that no empty entry will be appended to the vector if
 * the password is missing.
 *
 * @param options   parsed option list
 * @param opt_name  name of the option to interpret
 * @param flags     SplitLines::Flags, only OPT_REQUIRED and TRY_FILE are used
 * @param user_pass vector of strings, user and password will be appended if present
 * @return bool     True if the option was present, False otherwise
 */
inline bool parse(const OptionList &options,
                  const std::string &opt_name,
                  const unsigned int flags,
                  std::vector<std::string> *user_pass)
{
    const Option *auth_user_pass = options.get_ptr(opt_name);
    if (!auth_user_pass)
    {
        if (flags & OPT_REQUIRED)
            throw creds_error(opt_name + " : credentials option missing");
        return false;
    }
    if (auth_user_pass->size() == 1 && !(flags & OPT_REQUIRED))
        return true;
    if (auth_user_pass->size() != 2)
        throw creds_error(opt_name + " : credentials option incorrectly specified");

    std::string str = auth_user_pass->get(1, 1024 | Option::MULTILINE);
    if ((flags & TRY_FILE) && !string::is_multiline(str))
        str = read_text_utf8(str);
    SplitLines in(str, 1024);
    for (int i = 0; in(true) && i < 2; ++i)
    {
        if (user_pass)
            user_pass->push_back(in.line_move());
    }
    return true;
}

/**
 * @brief interpret user-pass option
 *
 * If the option is present without argument, then returns true unless
 * OPT_REQUIRED flag set. If OPT_REQUIRED flag is set, the option needs
 * to have exactly one argument.
 *
 * The argument might be specified as a multiline argument. I.e.
 * <opt_name>
 * username
 * password
 * </opt_name>
 *
 * The multiline argument is allowed to be 1024 UTF-8 characters in
 * length. If it is longer, the function will throw an exception.
 *
 * If the TRY_FILE flag is set and the argument is not multiline,
 * then it is interpreted as a filepath and the contents of the file
 * will replace the argument.
 *
 * Lines in the file are only allowed to be 1024 bytes in length.
 * Longer lines will cause an exception to be thrown.
 *
 * If the argument contains a newline, then the first line is used as the
 * username and the second line is used as the password, otherwise the argument
 * is the username.
 *
 * If USERNAME_REQUIRED and/or PASSWORD_REQUIRED flag is set, and the option is
 * present, then it will throw creds_error instead of returning empty values.
 * If the option is not present, it will only throw if OPT_OPTIONAL flag is not
 * set. If neither USERNAME_REQUIRED nor PASSWORD_REQUIRED flag are set, then
 * OPT_OPTIONAL has no effect.
 *
 * @param options   parsed option list
 * @param opt_name  name of the option to interpret
 * @param flags     SplitLines::Flags, all flags are used
 * @param user      Returns the username, if present. Otherwise empty
 * @param pass      Returns the password, if present. Otherwise empty
 */
inline void parse(const OptionList &options,
                  const std::string &opt_name,
                  const unsigned int flags,
                  std::string &user,
                  std::string &pass)
{
    user.clear();
    pass.clear();
    std::vector<std::string> up;
    up.reserve(2);
    if (!parse(options, opt_name, flags, &up) && (flags & OPT_OPTIONAL))
        return;
    if (up.size() >= 1)
    {
        user = std::move(up[0]);
        if (up.size() >= 2)
            pass = std::move(up[1]);
    }
    if ((flags & USERNAME_REQUIRED) && string::is_empty(user))
        throw creds_error(opt_name + " : username empty");
    if ((flags & PASSWORD_REQUIRED) && string::is_empty(pass))
        throw creds_error(opt_name + " : password empty");
}

/**
 * @brief read username/password from file
 *
 * If the file contents contain a newline, then the first line is used as the
 * username and the second line is used as the password, otherwise the content
 * is the username.
 *
 * Lines in the file are only allowed to be 1024 bytes in length.
 * Longer lines will cause an exception to be thrown.
 *
 * If USERNAME_REQUIRED and/or PASSWORD_REQUIRED flag is set, then it will throw
 * creds_error instead of returning empty values.
 *
 * @param path   file path
 * @param flags  SplitLines::Flags, only *_REQUIRED flags are relevant
 * @param user   Returns the username, if present. Otherwise empty
 * @param pass   Returns the password, if present. Otherwise empty
 */
inline void parse_file(const std::string &path,
                       const unsigned int flags,
                       std::string &user,
                       std::string &pass)
{
    user.clear();
    pass.clear();
    const std::string str = read_text_utf8(path);
    SplitLines in(str, 1024);
    if (in(true))
    {
        user = in.line_move();
        if (in(true))
            pass = in.line_move();
    }
    if ((flags & USERNAME_REQUIRED) && string::is_empty(user))
        throw creds_error(path + " : username empty");
    if ((flags & PASSWORD_REQUIRED) && string::is_empty(pass))
        throw creds_error(path + " : password empty");
}

} // namespace UserPass
} // namespace openvpn

#endif
