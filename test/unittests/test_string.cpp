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

#include "test_common.hpp"

#include <openvpn/common/string.hpp>

using namespace openvpn;

TEST(ovpn_string_suite, test_args_to_string_empty)
{
    const auto str = string::args_to_string(", ");
    EXPECT_EQ(str, "");
}

TEST(ovpn_string_suite, test_args_to_string_one)
{
    const auto str = string::args_to_string(", ", "a");
    EXPECT_EQ(str, "a");
}

TEST(ovpn_string_suite, test_args_to_string_two)
{
    const auto str = string::args_to_string(", ", "a", "b");
    EXPECT_EQ(str, "a, b");
}

TEST(ovpn_string_suite, test_args_to_string_three)
{
    const auto str = string::args_to_string(", ", "a", "b", "c");
    EXPECT_EQ(str, "a, b, c");
}

TEST(ovpn_string_suite, test_args_to_string_four)
{
    const auto str = string::args_to_string(", ", "a", "b", "c", "d");
    EXPECT_EQ(str, "a, b, c, d");
}

TEST(ovpn_string_suite, test_args_to_string_two_mixed)
{
    const auto str = string::args_to_string(", ", "a", 1);
    EXPECT_EQ(str, "a, 1");
}

TEST(ovpn_string_suite, test_args_to_string_three_mixed)
{
    const auto str = string::args_to_string("", "a", 1, "b");
    EXPECT_EQ(str, "a1b");
}

TEST(ovpn_string_suite, test_format_safe_empty)
{
    const auto str = string::format_safe("");
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "");
}

TEST(ovpn_string_suite, test_format_safe_zero)
{
    const auto str = string::format_safe("a");
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a");
}

TEST(ovpn_string_suite, test_format_safe_one)
{
    const auto str = string::format_safe("a {}", 1);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1");
}

TEST(ovpn_string_suite, test_format_safe_two)
{
    const auto str = string::format_safe("a {} {}", 1, 2);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1 2");
}

TEST(ovpn_string_suite, test_format_safe_three)
{
    const auto str = string::format_safe("a {} {} {}", 1, "2", 3);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1 2 3");
}

TEST(ovpn_string_suite, test_format_safe_malformed)
{
    const auto str = string::format_safe("a } {} {} {}", 1, "2", 3);
    EXPECT_FALSE(str);
}

TEST(ovpn_string_suite, test_format_safe_malformed2)
{
    const auto str = string::format_safe("a {} {} {} {}", 1, "2", 3);
    EXPECT_FALSE(str);
}
