
//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2024- OpenVPN Inc.
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
//
//
//    Basic unit test for the openvpn/openssl/pki/x509certinfo.hpp functions
//

#include "test_common.hpp"

#include <openvpn/common/optional_ref.hpp>


struct test_optional
{
    int i = 0;
};

TEST(optional_ref_suite, simple)
{
    int i = 42;
    auto o = openvpn::optional<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
}

TEST(optional_ref_suite, simple_const)
{
    const int i = 42;
    auto o = openvpn::optional<const int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
}

TEST(optional_ref_suite, assign_to)
{
    int i = 42;
    auto o = openvpn::optional<int &>(i);
    int j = 0;
    o = openvpn::optional<int &>(j);
    j = 96;
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), j);
    EXPECT_EQ(*o, j);
}

TEST(optional_ref_suite, assign_thru)
{
    int i = 42;
    auto o = openvpn::optional<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(42, *o);
    *o = 96;
    EXPECT_EQ(i, 96);
}

TEST(optional_ref_suite, assign_ptr_thru)
{
    int i = 42;
    auto o = openvpn::optional<int &>(&i);
    EXPECT_TRUE(o);
    EXPECT_EQ(42, *o);
    *o = 96;
    EXPECT_EQ(i, 96);
}

TEST(optional_ref_suite, invalid)
{
    auto o = openvpn::optional<int &>();
    EXPECT_THROW(o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}

TEST(optional_ref_suite, invalid_nullopt)
{
    auto o = openvpn::optional<int &>(std::nullopt);
    EXPECT_THROW(o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}

TEST(optional_ref_suite, assign_nullopt)
{
    int i = 42;
    auto o = openvpn::optional<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
    o = std::nullopt;
    EXPECT_THROW(o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}


TEST(optional_ref_suite, value_or)
{
    int i = 42;
    auto o = openvpn::optional<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value_or(96), 42);
}

TEST(optional_ref_suite, value_or_default)
{
    auto o = openvpn::optional<int &>(std::nullopt);
    EXPECT_FALSE(o);
    EXPECT_EQ(o.value_or(42), 42);
}

TEST(optional_ref_suite, value_or_default_lvalue)
{
    auto o = openvpn::optional<int &>(std::nullopt);
    EXPECT_FALSE(o);
    int i = 42;
    EXPECT_EQ(o.value_or(i), i);
}

TEST(optional_ref_suite, deref)
{
    auto t = test_optional();
    auto o = openvpn::optional<test_optional &>(t);
    EXPECT_EQ(o->i, 0);
    o->i = 42;
    EXPECT_EQ(o->i, 42);
}

TEST(optional_ref_suite, deref_invalid)
{
    auto o = openvpn::optional<test_optional &>();
    EXPECT_FALSE(o);
    EXPECT_ANY_THROW([[maybe_unused]] auto t = o->i);
}
