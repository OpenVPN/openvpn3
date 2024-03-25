//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2024 OpenVPN Inc.
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

#pragma once

#ifdef _WIN32

#include <string>
#include <vector>
#include <memory>

namespace openvpn {
namespace wstring {

inline std::wstring from_utf8(const std::string &str)
{
    std::wstring wStr; // enable RVO
    if (str.empty())
        return wStr;
    const auto reqSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (reqSize == 0)
        throw std::runtime_error("MultiByteToWideChar(1) failed with code: [" + std::to_string(::GetLastError()) + "]");
    wStr.resize(reqSize, L'\0'); // Allocate space
    if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wStr[0], reqSize) == 0)
        throw std::runtime_error("MultiByteToWideChar(2) failed with code: [" + std::to_string(::GetLastError()) + "]");
    return wStr;
}

inline std::string to_utf8(const std::wstring &wstr)
{
    std::string str; // For RVO
    if (wstr.empty())
        return str;
    const auto reqSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (reqSize == 0)
        throw std::runtime_error("WideCharToMultiByte(1) failed with code: [" + std::to_string(::GetLastError()) + "]");
    str.resize(reqSize, '\0'); // Allocate space
    if (WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], reqSize, nullptr, nullptr) == 0)
        throw std::runtime_error("WideCharToMultiByte(2) failed with code: [" + std::to_string(::GetLastError()) + "]");
    return str;
}

inline std::unique_ptr<wchar_t[]> to_wchar_t(const std::wstring &wstr)
{
    const size_t len = wstr.length();
    std::unique_ptr<wchar_t[]> ret(new wchar_t[len + 1]);
    size_t i;
    for (i = 0; i < len; ++i)
        ret[i] = wstr[i];
    ret[i] = L'\0';
    return ret;
}

// return value corresponds to the MULTI_SZ string format on Windows
inline std::wstring pack_string_vector(const std::vector<std::string> &strvec)
{
    std::wstring ret;
    for (auto &s : strvec)
    {
        ret += from_utf8(s);
        ret += L'\0';
    }
    return ret;
}

#endif // #ifdef _WIN32

} // namespace wstring
} // namespace openvpn
