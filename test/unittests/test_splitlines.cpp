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

#include <openvpn/common/splitlines.hpp>

using namespace openvpn;

const std::string short_text = "Lorem\nipsum\r\ndolor\n\r\nsit";
const std::vector<std::string> short_lines{"Lorem\n", "ipsum\r\n", "dolor\n", "\r\n", "sit"};
const std::vector<std::string> short_lines_trim{"Lorem", "ipsum", "dolor", "", "sit"};

TEST(SplitLines, NoMaxLengthNoTrim)
{
    SplitLines in(short_text, 0);
    size_t index = 0;
    while (in(false))
    {
        ASSERT_EQ(in.line_ref(), short_lines[index++]);
    }
}

TEST(SplitLines, NextNoMaxLengthNoTrim)
{
    SplitLines in(short_text, 0);
    size_t index = 0;
    std::string line;
    SplitLines::Status ret = SplitLines::S_OKAY;
    while ((ret = in.next(line, false)) != SplitLines::S_EOF)
    {
        ASSERT_EQ(ret, SplitLines::S_OKAY);
        ASSERT_EQ(line, short_lines[index++]);
    }
}

TEST(SplitLines, NoMaxLengthTrim)
{
    SplitLines in(short_text, 0);
    size_t index = 0;
    while (in(true))
    {
        ASSERT_FALSE(in.line_overflow());
        ASSERT_EQ(in.line_ref(), short_lines_trim[index++]);
    }
}

TEST(SplitLines, NextNoMaxLengthTrim)
{
    SplitLines in(short_text, 0);
    size_t index = 0;
    std::string line;
    SplitLines::Status ret = SplitLines::S_OKAY;
    while ((ret = in.next(line, true)) != SplitLines::S_EOF)
    {
        ASSERT_EQ(ret, SplitLines::S_OKAY);
        ASSERT_EQ(line, short_lines_trim[index++]);
    }
}

TEST(SplitLines, MaxLength)
{
    SplitLines in(short_text, 24);
    size_t index = 0;
    while (in(true))
    {
        ASSERT_FALSE(in.line_overflow());
        ASSERT_EQ(in.line_ref(), short_lines_trim[index++]);
    }
}

TEST(SplitLines, NextMaxLength)
{
    SplitLines in(short_text, 24);
    size_t index = 0;
    std::string line;
    SplitLines::Status ret = SplitLines::S_OKAY;
    while ((ret = in.next(line, true)) != SplitLines::S_EOF)
    {
        ASSERT_EQ(ret, SplitLines::S_OKAY);
        ASSERT_EQ(line, short_lines_trim[index++]);
    }
}

TEST(SplitLines, MaxLengthOverflow)
{
    SplitLines in(short_text, 3);
    ASSERT_TRUE(in(true));
    ASSERT_TRUE(in.line_overflow());
    ASSERT_THROW(in.line_ref(), SplitLines::overflow_error);
}

TEST(SplitLines, NextMaxLengthOverflow)
{
    SplitLines in(short_text, 3);
    std::string line;
    ASSERT_EQ(in.next(line, true), SplitLines::S_ERROR);
}

TEST(SplitLines, MovedError)
{
    SplitLines in(short_text);
    ASSERT_TRUE(in(true));
    ASSERT_FALSE(in.line_overflow());
    const std::string line = in.line_move();
    ASSERT_THROW(in.line_ref(), SplitLines::moved_error);
}
