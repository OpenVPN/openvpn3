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

#include <openvpn/common/clamp_typerange.hpp>

using namespace openvpn::numeric_util;


/* ============================================================================================================= */
//  clamp_to_typerange
/* ============================================================================================================= */


TEST(ClampToTyperange, SameTypeNocast1)
{
    const int32_t i32 = -1;
    auto result = clamp_to_typerange<int32_t>(i32);
    EXPECT_EQ(result, i32);
}

TEST(ClampToTyperange, SignMismatch321)
{
    const int32_t i32 = -1;
    auto result = clamp_to_typerange<uint32_t>(i32);
    EXPECT_EQ(result, 0);
}

TEST(ClampToTyperange, SignMismatch322)
{
    const uint32_t u32 = std::numeric_limits<uint32_t>::max();
    auto result = clamp_to_typerange<int32_t>(u32);
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());
}

TEST(ClampToTyperange, SignMismatch323)
{
    const uint32_t u32 = 0;
    auto result = clamp_to_typerange<int32_t>(u32);
    EXPECT_EQ(result, 0);
}

TEST(ClampToTyperange, SignMismatch324)
{
    const uint32_t u32 = 42;
    auto result = clamp_to_typerange<int32_t>(u32);
    EXPECT_EQ(result, 42);
}

TEST(ClampToTyperange, SignMismatch325)
{
    const uint32_t u32 = uint32_t(std::numeric_limits<int32_t>::max());
    auto result = clamp_to_typerange<int32_t>(u32);
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());
}

TEST(ClampToTyperange, SignMismatch326)
{
    const int32_t s32 = std::numeric_limits<int32_t>::max();
    auto result = clamp_to_typerange<uint8_t>(s32);
    EXPECT_EQ(result, std::numeric_limits<uint8_t>::max());
}

TEST(ClampToTyperange, SignMismatch327)
{
    const int32_t s32 = 42;
    auto result = clamp_to_typerange<uint8_t>(s32);
    EXPECT_EQ(result, 42);
}

TEST(ClampToTyperange, SRangeMismatch16641)
{
    const int64_t s64 = std::numeric_limits<int64_t>::max();
    auto result = clamp_to_typerange<int16_t>(s64);
    EXPECT_EQ(result, std::numeric_limits<int16_t>::max());
}

TEST(ClampToTyperange, SRangeMatch16641)
{
    const int64_t s64 = 0;
    auto result = clamp_to_typerange<int16_t>(s64);
    EXPECT_EQ(result, 0);
}

TEST(ClampToTyperange, URangeMismatch16641)
{
    const uint64_t u64 = std::numeric_limits<uint64_t>::max();
    auto result = clamp_to_typerange<uint16_t>(u64);
    EXPECT_EQ(result, std::numeric_limits<uint16_t>::max());
}


/* ============================================================================================================= */
//  clamp_to_default
/* ============================================================================================================= */


TEST(ClampToDefault, SameTypeNocast1)
{
    const int32_t i32 = -1;
    auto result = clamp_to_default<int32_t>(i32, 0);
    EXPECT_EQ(result, i32);
}

TEST(ClampToDefault, SignMismatch321)
{
    const int32_t i32 = -1;
    auto result = clamp_to_default<uint32_t>(i32, 42);
    EXPECT_EQ(result, 42);
}

TEST(ClampToDefault, SignMismatch322)
{
    const uint32_t u32 = std::numeric_limits<uint32_t>::max();
    auto result = clamp_to_default<int32_t>(u32, 1);
    EXPECT_EQ(result, 1);
}

TEST(ClampToDefault, SignMismatch323)
{
    const uint32_t u32 = 0;
    auto result = clamp_to_default<int32_t>(u32, 42);
    EXPECT_EQ(result, 0);
}

TEST(ClampToDefault, SignMismatch324)
{
    const uint32_t u32 = 42;
    auto result = clamp_to_default<int32_t>(u32, 0);
    EXPECT_EQ(result, 42);
}

TEST(ClampToDefault, SignMismatch325)
{
    const uint32_t u32 = uint32_t(std::numeric_limits<int32_t>::max());
    auto result = clamp_to_default<int32_t>(u32, -1);
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());
}

TEST(ClampToDefault, SignMismatch326)
{
    const int32_t s32 = std::numeric_limits<int32_t>::max();
    auto result = clamp_to_default<uint8_t>(s32, 0);
    EXPECT_EQ(result, 0);
}

TEST(ClampToDefault, SignMismatch327)
{
    const int32_t s32 = 42;
    auto result = clamp_to_default<uint8_t>(s32, -1);
    EXPECT_EQ(result, 42);
}

TEST(ClampToDefault, SRangeMismatch16641)
{
    const int64_t s64 = std::numeric_limits<int64_t>::max();
    auto result = clamp_to_default<int16_t>(s64, 0);
    EXPECT_EQ(result, 0);
}

TEST(ClampToDefault, SRangeMatch16641)
{
    const int64_t s64 = 0;
    auto result = clamp_to_default<int16_t>(s64, -1);
    EXPECT_EQ(result, 0);
}

TEST(ClampToDefault, URangeMismatch16641)
{
    const uint64_t u64 = std::numeric_limits<uint64_t>::max();
    auto result = clamp_to_default<uint16_t>(u64, 42);
    EXPECT_EQ(result, 42);
}

/* ============================================================================================================= */
//  clamp_notify
/* ============================================================================================================= */


TEST(ClampNotify, SameTypeNocast1)
{
    const int32_t i32 = -1;
    auto result = clamp_notify<int32_t>(i32, [](int32_t inVal)
                                        { return 0; });
    EXPECT_EQ(result, i32);
}

TEST(ClampNotify, SignMismatch321)
{
    const int32_t i32 = -1;
    auto result = clamp_notify<uint32_t>(i32, [](int32_t inVal)
                                         { return 42; });
    EXPECT_EQ(result, 42);
}

TEST(ClampNotify, SignMismatch322)
{
    const uint32_t u32 = std::numeric_limits<uint32_t>::max();
    auto result = clamp_notify<int32_t>(u32, [](uint32_t inVal)
                                        { return 1; });
    EXPECT_EQ(result, 1);
}

TEST(ClampNotify, SignMismatch323)
{
    const uint32_t u32 = 0;
    auto result = clamp_notify<int32_t>(u32, [](uint32_t inVal)
                                        { return 42; });
    EXPECT_EQ(result, 0);
}

TEST(ClampNotify, SignMismatch324)
{
    const uint32_t u32 = 42;
    auto result = clamp_notify<int32_t>(u32, [](uint32_t inVal)
                                        { return 0; });
    EXPECT_EQ(result, 42);
}

TEST(ClampNotify, SignMismatch325)
{
    const uint32_t u32 = uint32_t(std::numeric_limits<int32_t>::max());
    auto result = clamp_notify<int32_t>(u32, [](uint32_t inVal)
                                        { return -1; });
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());
}

TEST(ClampNotify, SignMismatch326)
{
    const int32_t s32 = std::numeric_limits<int32_t>::max();
    auto result = clamp_notify<uint8_t>(s32, [](int32_t inVal) -> uint8_t
                                        { return 0; });
    EXPECT_EQ(result, 0);
}

TEST(ClampNotify, SignMismatch327)
{
    const int32_t s32 = 42;
    auto result = clamp_notify<uint8_t>(s32, [](int32_t inVal) -> uint8_t
                                        { return 0; });
    EXPECT_EQ(result, 42);
}

TEST(ClampNotify, SRangeMismatch16641)
{
    const int64_t s64 = std::numeric_limits<int64_t>::max();
    auto result = clamp_notify<int16_t>(s64, [](int64_t inVal) -> int16_t
                                        { return 0; });
    EXPECT_EQ(result, 0);
}

TEST(ClampNotify, SRangeMatch16641)
{
    const int64_t s64 = 0;
    auto result = clamp_notify<int16_t>(s64, [](int64_t inVal) -> int16_t
                                        { return -1; });
    EXPECT_EQ(result, 0);
}

TEST(ClampNotify, URangeMismatch16641)
{
    const uint64_t u64 = std::numeric_limits<uint64_t>::max();
    auto result = clamp_notify<uint16_t>(u64, [](uint64_t inVal) -> uint16_t
                                         { return 42; });
    EXPECT_EQ(result, 42);
}
