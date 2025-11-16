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

TEST(OvpnStringSuite, TestArgsToStringEmpty)
{
    const auto str = string::args_to_string(", ");
    EXPECT_EQ(str, "");
}

TEST(OvpnStringSuite, TestArgsToStringOne)
{
    const auto str = string::args_to_string(", ", "a");
    EXPECT_EQ(str, "a");
}

TEST(OvpnStringSuite, TestArgsToStringTwo)
{
    const auto str = string::args_to_string(", ", "a", "b");
    EXPECT_EQ(str, "a, b");
}

TEST(OvpnStringSuite, TestArgsToStringThree)
{
    const auto str = string::args_to_string(", ", "a", "b", "c");
    EXPECT_EQ(str, "a, b, c");
}

TEST(OvpnStringSuite, TestArgsToStringFour)
{
    const auto str = string::args_to_string(", ", "a", "b", "c", "d");
    EXPECT_EQ(str, "a, b, c, d");
}

TEST(OvpnStringSuite, TestArgsToStringTwoMixed)
{
    const auto str = string::args_to_string(", ", "a", 1);
    EXPECT_EQ(str, "a, 1");
}

TEST(OvpnStringSuite, TestArgsToStringThreeMixed)
{
    const auto str = string::args_to_string("", "a", 1, "b");
    EXPECT_EQ(str, "a1b");
}

TEST(OvpnStringSuite, TestFormatSafeEmpty)
{
    const auto str = string::format_safe("");
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "");
}

TEST(OvpnStringSuite, TestFormatSafeZero)
{
    const auto str = string::format_safe("a");
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a");
}

TEST(OvpnStringSuite, TestFormatSafeOne)
{
    const auto str = string::format_safe("a {}", 1);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1");
}

TEST(OvpnStringSuite, TestFormatSafeTwo)
{
    const auto str = string::format_safe("a {} {}", 1, 2);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1 2");
}

TEST(OvpnStringSuite, TestFormatSafeThree)
{
    const auto str = string::format_safe("a {} {} {}", 1, "2", 3);
    EXPECT_TRUE(str);
    EXPECT_EQ(*str, "a 1 2 3");
}

TEST(OvpnStringSuite, TestFormatSafeMalformed)
{
    const auto str = string::format_safe("a } {} {} {}", 1, "2", 3);
    EXPECT_FALSE(str);
}

TEST(OvpnStringSuite, TestFormatSafeMalformed2)
{
    const auto str = string::format_safe("a {} {} {} {}", 1, "2", 3);
    EXPECT_FALSE(str);
}
