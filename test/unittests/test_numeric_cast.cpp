//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2023- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//



#include "test_common.hpp"

#include <cstdint>
#include <cctype>

#include <openvpn/common/numeric_cast.hpp>


using namespace openvpn::numeric_util;


TEST(NumericCast, SameTypeNocast1)
{
    const int32_t i32 = -1;
    auto result = numeric_cast<int32_t>(i32);
    EXPECT_EQ(result, i32);
}

TEST(NumericCast, SignMismatch321)
{
    const int32_t i32 = -1;
    EXPECT_THROW(numeric_cast<uint32_t>(i32), numeric_out_of_range);
}

TEST(NumericCast, SignMismatch322)
{
    const uint32_t u32 = std::numeric_limits<uint32_t>::max();
    EXPECT_THROW(numeric_cast<int32_t>(u32), numeric_out_of_range);
}

TEST(NumericCast, SignMismatch323)
{
    const uint32_t u32 = 0;
    auto result = numeric_cast<int32_t>(u32);
    EXPECT_EQ(result, 0);
}

TEST(NumericCast, SignMismatch324)
{
    const uint32_t u32 = 42;
    auto result = numeric_cast<int32_t>(u32);
    EXPECT_EQ(result, 42);
}

TEST(NumericCast, SignMismatch325)
{
    const uint32_t u32 = uint32_t(std::numeric_limits<int32_t>::max());
    auto result = numeric_cast<int32_t>(u32);
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());
}

TEST(NumericCast, SignMismatch326)
{
    const int32_t s32 = std::numeric_limits<int32_t>::max();
    EXPECT_THROW(numeric_cast<uint8_t>(s32), numeric_out_of_range);
}

TEST(NumericCast, SignMismatch327)
{
    const int32_t s32 = 42;
    auto result = numeric_cast<uint8_t>(s32);
    EXPECT_EQ(result, 42);
}

TEST(NumericCast, SRangeMismatch16641)
{
    const int64_t s64 = std::numeric_limits<int64_t>::max();
    EXPECT_THROW(numeric_cast<int16_t>(s64), numeric_out_of_range);
}

TEST(NumericCast, SRangeMatch16641)
{
    const int64_t s64 = 0;
    auto result = numeric_cast<int16_t>(s64);
    EXPECT_EQ(result, 0);
}

TEST(NumericCast, URangeMismatch16641)
{
    const uint64_t u64 = std::numeric_limits<uint64_t>::max();
    EXPECT_THROW(numeric_cast<uint16_t>(u64), numeric_out_of_range);
}
