//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2026- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include <gtest/gtest.h>

#include "test_common.hpp"
#include "test_generators.hpp"

#include <rapidcheck/state.h>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/buffer/bufstream.hpp>
#include <openvpn/buffer/bufstr.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <iosfwd>
#include <istream>
#include <iterator>
#include <limits>
#include <memory>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace BufAllocFlags = openvpn::BufAllocFlags;
using openvpn::buf_to_string;
using openvpn::BufferAllocated;
using openvpn::BufferStream;
using openvpn::BufferStreamInOut;
using openvpn::BufferStreamOut;

namespace {

//! What the streambuf protocol returns for a seek it cannot satisfy.
std::streambuf::pos_type bad_pos()
{
    return {std::streambuf::off_type{-1}};
}

//! Exposes the get area so a regression shows up as a failure rather than a hung run:
//! a reader-only test of the same property spins forever instead of returning.
struct GetAreaProbe : BufferStream
{
    using BufferStream::BufferStream;
    using BufferStream::egptr;
    using BufferStream::gptr;
    using BufferStream::underflow;
};

//! Exposes overflow(), which sputc() cannot reach with EOF: it converts what it is
//! handed through to_int_type() first.
struct OverflowProbe : BufferStream
{
    using BufferStream::BufferStream;
    using BufferStream::overflow;
};

//! Read whatever is left, from the current read position to the end.
std::string drain(std::istream &stream)
{
    EXPECT_TRUE(stream.good()) << "drain() reads past the stream state; check it first";
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(BufferStream, TellAndReadBack)
{
    BufferAllocated buf(8, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    // Longer than the initial capacity, so the write reallocates on the way in.
    const std::string body(200, 'x');
    ios << body;
    ios.flush();

    EXPECT_EQ(ios.tellp(), std::streampos(body.size()));
    EXPECT_EQ(ios.tellg(), std::streampos(0));
    EXPECT_EQ(drain(ios), body);

    // Reading must leave the buffer whole for its owner.
    EXPECT_EQ(buf_to_string(buf), body);
}

TEST(BufferStream, RereadAfterSeekg)
{
    BufferAllocated buf(64, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    const std::string body("the quick brown fox");
    ios << body;
    ios.flush();

    EXPECT_EQ(drain(ios), body);

    ios.seekg(0);
    EXPECT_EQ(ios.tellg(), std::streampos(0));
    EXPECT_EQ(drain(ios), body);
}

TEST(BufferStream, PartialReadAndRelativeSeeks)
{
    BufferAllocated buf(64, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    const std::string body("0123456789");
    ios << body;
    ios.flush();

    std::array<char, 4> head{};
    ios.read(head.data(), head.size());
    ASSERT_EQ(ios.gcount(), head.size());
    EXPECT_EQ(std::string(head.data(), head.size()), "0123");
    EXPECT_EQ(ios.tellg(), std::streampos(head.size()));

    ios.seekg(2, std::ios_base::cur);
    EXPECT_EQ(ios.tellg(), std::streampos(head.size() + 2));

    // A bulk read (xsgetn) from a position seeked to rather than from the start.
    ios.seekg(-3, std::ios_base::end);
    EXPECT_EQ(ios.tellg(), std::streampos(7));
    std::array<char, 3> tail{};
    ios.read(tail.data(), tail.size());
    ASSERT_EQ(ios.gcount(), tail.size());
    EXPECT_EQ(std::string(tail.data(), tail.size()), "789");
    EXPECT_EQ(ios.tellg(), std::streampos(10));

    ios.seekg(0, std::ios_base::end);
    EXPECT_EQ(ios.tellg(), std::streampos(body.size()));
}

TEST(BufferStream, OutOfRangeSeeksFail)
{
    BufferAllocated buf(64, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "12345";
    ios.flush();

    // Must fail rather than clamp, or a reader lands on whatever is either side.
    ios.seekg(6);
    EXPECT_TRUE(ios.fail());

    ios.clear();
    ios.seekg(-1, std::ios_base::beg);
    EXPECT_TRUE(ios.fail());

    // The end itself is legal: it is where a completed read lands.
    ios.clear();
    ios.seekg(5);
    EXPECT_TRUE(ios.good());
    EXPECT_EQ(ios.tellg(), std::streampos(5));
}

TEST(BufferStream, HighBitBytesRoundTrip)
{
    BufferAllocated buf(4, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    // 0xff must not come back as EOF, nor 0x80 as a negative char: either truncates
    // at the first non-ASCII byte.
    const std::string raw("\x00\x7f\x80\xff\xfe", 5);
    ios.write(raw.data(), static_cast<std::streamsize>(raw.size()));
    ios.flush();

    EXPECT_EQ(ios.tellp(), std::streampos(5));
    EXPECT_EQ(drain(ios), raw);

    // And through underflow() itself: the drain took every byte but the first out of a
    // get area already published, where the base class does its own conversion.  A seek
    // drops the area, so the byte after it comes back through the cast here.
    ios.seekg(3);
    EXPECT_EQ(ios.get(), 0xff);
}

TEST(BufferStream, EmptyBufferTellsZero)
{
    BufferAllocated buf(4, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    EXPECT_EQ(ios.tellp(), std::streampos(0));
    EXPECT_EQ(ios.get(), std::istream::traits_type::eof());
}

TEST(BufferStream, RepeatedReadsAtEofStayPut)
{
    BufferAllocated buf(64, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "ab";
    ios.flush();
    EXPECT_EQ(drain(ios), "ab");

    // Asking again must not walk the read position past the end.
    for (int i = 0; i < 3; ++i)
    {
        ios.clear();
        EXPECT_EQ(ios.get(), std::istream::traits_type::eof());
    }
    // codechecker_false_positive [alpha.deadcode.UnreachableCode] reached once the three-pass loop ends
    ios.clear();
    EXPECT_EQ(ios.tellg(), std::streampos(2));
}

TEST(BufferStream, AppendWhileReadingAcrossRealloc)
{
    // An append through the streambuf can move the buffer mid-read.  The get area that
    // get() published over the old storage has to go with it, so the next read finds
    // the new base pointer rather than chasing the old one.
    BufferAllocated buf(8, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    const std::string first(4, 'a');
    ios << first;
    ios.flush();

    // Not tellg() before the append: its seekoff() would drop the area first.
    ASSERT_EQ(ios.get(), 'a');
    ASSERT_EQ(ios.get(), 'a');

    const size_t capacity_before = buf.capacity();
    const std::string second(4096, 'b');
    ios << second;
    ios.flush();
    // codechecker_false_positive [cppcheck-knownConditionTrueFalse] the append above grows buf through the stream
    ASSERT_GT(buf.capacity(), capacity_before) << "the append must reallocate";

    // The write moved neither the read position nor the bytes behind it.
    EXPECT_EQ(ios.tellg(), std::streampos(2));
    EXPECT_EQ(ios.tellp(), std::streampos(first.size() + second.size()));
    EXPECT_EQ(drain(ios), first.substr(2) + second);
}

TEST(BufferStream, Putback)
{
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "abc";
    ios.flush();

    EXPECT_EQ(ios.get(), 'a');
    EXPECT_EQ(ios.get(), 'b');

    ios.unget();
    EXPECT_TRUE(ios.good());
    EXPECT_EQ(ios.tellg(), std::streampos(1));
    EXPECT_EQ(ios.get(), 'b');

    // The byte that is there goes back...
    ios.putback('b');
    EXPECT_TRUE(ios.good());
    EXPECT_EQ(ios.get(), 'b');

    // ...anything else fails rather than rewriting the caller's buffer.
    ios.putback('z');
    EXPECT_TRUE(ios.fail());
    ios.clear();
    EXPECT_EQ(buf_to_string(buf), "abc");

    // Nothing to put back at the start.
    ios.seekg(0);
    ios.unget();
    EXPECT_TRUE(ios.fail());
}

TEST(BufferStream, PutbackOfAHighBitByte)
{
    // Through pbackfail(): a bulk read leaves no get area, so sputbackc() cannot take
    // its in-area shortcut and the byte is compared against the buffer itself.  Read
    // from there as a signed char, 0xfe matches nothing and the putback is refused.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    const std::string raw("\x01\x02\x03\x04\xfe", 5);
    ios.write(raw.data(), static_cast<std::streamsize>(raw.size()));
    ios.flush();

    std::array<char, 5> got{};
    ios.read(got.data(), got.size());
    ASSERT_EQ(ios.gcount(), got.size());

    ios.putback('\xfe');
    EXPECT_TRUE(ios.good());
    EXPECT_EQ(ios.get(), 0xfe);
}

TEST(BufferStream, ReadsomeReportsWhatIsAvailable)
{
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "hello";
    ios.flush();

    std::array<char, 8> got{};
    EXPECT_EQ(ios.readsome(got.data(), got.size()), 5);
    EXPECT_EQ(std::string(got.data(), 5), "hello");
    EXPECT_EQ(ios.readsome(got.data(), got.size()), 0);
    // 0 out of showmanyc(), not -1: readsome() returns 0 for both and tells them apart
    // only by the eofbit it sets for -1.
    EXPECT_TRUE(ios.good());
}

TEST(BufferStream, PutPositionAnswersTellOnly)
{
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::ostream out(&sbuf);

    out << "12345";
    out.flush();

    // tellp()'s own query.
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::cur, std::ios_base::out), std::streambuf::pos_type(5));

    // Writes always append, so the put position cannot be moved.
    EXPECT_EQ(sbuf.pubseekoff(1, std::ios_base::cur, std::ios_base::out), bad_pos());
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::beg, std::ios_base::out), bad_pos());
    EXPECT_EQ(sbuf.pubseekpos(0, std::ios_base::out), bad_pos());

    // in and out together: the two positions move independently, so there is no one
    // answer to give.
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::cur), bad_pos());
    EXPECT_EQ(sbuf.pubseekpos(0), bad_pos());
}

TEST(BufferStream, SeekPutToWhereItAlreadyIs)
{
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::ostream out(&sbuf);

    out << "12345";
    out.flush();

    // Saving and restoring the put position must be a no-op, not a failure: a failed
    // ostream discards everything written after it, silently.
    out.seekp(out.tellp());
    ASSERT_TRUE(out.good());
    out.seekp(0, std::ios_base::end);
    ASSERT_TRUE(out.good());

    out << "678";
    out.flush();
    EXPECT_EQ(buf_to_string(buf), "12345678");
}

namespace {
//! The owner consuming from the front must not shift what is left to read, at any
//! magnitude: the read position counts back from the end for this reason.  The
//! parameter is how many bytes the owner consumes.
class OwnerConsumesFront : public ::testing::TestWithParam<size_t>
{
};
} // namespace

TEST_P(OwnerConsumesFront, LeavesTheUndeliveredTailIntact)
{
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789";
    std::array<char, 4> head{};
    ios.read(head.data(), head.size());
    ASSERT_EQ(ios.gcount(), head.size());
    ASSERT_EQ(std::string(head.data(), head.size()), "0123");

    const size_t eaten = GetParam();
    buf.advance(eaten); // owner consumes what it has handled

    // "456789" is still owed unless the owner ate into it, in which case only what
    // survives is.  Either way, never a byte from behind the live region.
    const std::string owed("456789");
    const std::string expected = eaten <= 4 ? owed : owed.substr(std::min(eaten - 4, owed.size()));
    EXPECT_EQ(drain(ios), expected);
}

INSTANTIATE_TEST_SUITE_P(BufferStream, OwnerConsumesFront, ::testing::Values(0, 1, 4, 5, 9, 10));

TEST(BufferStream, BulkReadAfterTheOwnerConsumesFront)
{
    // A bulk read lands in xsgetn(), which no get area resync will correct after the
    // fact: what it takes off the count owed has to be what it delivered, not what was
    // left over from before the owner ate into the buffer.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789";
    std::array<char, 4> head{};
    ios.read(head.data(), head.size());
    ASSERT_EQ(ios.gcount(), head.size());

    buf.advance(5); // owner eats "01234", a byte past what was delivered

    std::array<char, 16> rest{};
    ios.read(rest.data(), rest.size()); // asks for more than is there, so eof and a short count
    EXPECT_EQ(ios.gcount(), 5);
    EXPECT_EQ(std::string(rest.data(), 5), "56789");

    ios.clear();                                            // the short read set eofbit
    EXPECT_EQ(ios.tellg(), std::streampos(5));              // the end, all of it read
    EXPECT_EQ(ios.get(), std::istream::traits_type::eof()); // and nothing replayed
}

TEST(BufferStream, OwnerShrinksPastTheReadPosition)
{
    // Once the owner has eaten everything owed, there is nothing to hand back and
    // nothing to put back, and still no read from behind the live region.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789";
    std::array<char, 8> head{};
    ios.read(head.data(), head.size());
    ASSERT_EQ(ios.gcount(), 8);

    buf.advance(10); // everything, the two undelivered bytes included

    ios.unget();
    EXPECT_TRUE(ios.fail());

    ios.clear();
    EXPECT_EQ(ios.get(), std::istream::traits_type::eof());

    ios.clear();
    EXPECT_EQ(ios.tellg(), std::streampos(0));
}

TEST(BufferStream, SeekgResyncsAfterMidReadMutation)
{
    // The owner-mutation tests above mutate before any get area is up.  Here one is,
    // and the base class serves reads out of it without calling in: the window the class
    // comment warns about, so what a read returns inside it is not pinned here.  seekg()
    // is the documented way back out.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789";
    ASSERT_EQ(ios.get(), '0'); // publishes a get area over the whole body

    buf.advance(5); // what the owner has left is "56789"

    ios.seekg(0);
    EXPECT_EQ(drain(ios), "56789");
}

TEST(BufferStream, OwnerResetsAndRefills)
{
    // reset_size() then a fresh write is how a retrying owner reuses one buffer; the
    // reader must see the new body, not a position stranded past it.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789";
    EXPECT_EQ(drain(ios), "0123456789");

    buf.reset_size();
    ios << "abcde";

    EXPECT_EQ(ios.tellp(), std::streampos(5));
    EXPECT_EQ(ios.tellg(), std::streampos(0));
    EXPECT_EQ(drain(ios), "abcde");
}

TEST(BufferStream, UnallocatedBuffer)
{
    // A default-constructed Buffer has no storage at all, so c_data() is null.
    BufferAllocated buf;
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    EXPECT_EQ(ios.tellp(), std::streampos(0));

    std::array<char, 4> got{};
    ios.read(got.data(), got.size());
    EXPECT_EQ(ios.gcount(), 0);

    ios.clear();
    EXPECT_EQ(ios.readsome(got.data(), got.size()), 0);
    EXPECT_TRUE(ios.good()) << "no storage at all is 0 available, not -1";
    EXPECT_EQ(ios.get(), std::istream::traits_type::eof());
}

TEST(BufferStream, WriteOnlyUseIsUnchanged)
{
    // All this class could do before it grew a read side.
    BufferAllocated buf(4, BufAllocFlags::GROW);
    {
        BufferStreamOut out(buf);
        out << "This is a test of the " << 2014 << " zombie invasion.\n";
    }
    EXPECT_EQ(buf_to_string(buf), "This is a test of the 2014 zombie invasion.\n");
}

TEST(BufferStream, IstreambufIteratorAdvances)
{
    // underflow() must leave what it returns at gptr(): libstdc++'s std::advance loops
    // on egptr() - gptr(), so a get area that is never published spins forever.
    BufferAllocated buf(64, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "0123456789abcdef";

    std::istreambuf_iterator<char> iter(ios);
    std::advance(iter, 4);
    EXPECT_EQ(*iter, '4');

    // The same path std::getline and operator>> take.
    ios.seekg(0);
    std::string line;
    ASSERT_TRUE(std::getline(ios, line));
    EXPECT_EQ(line, "0123456789abcdef");
}

TEST(BufferStream, SeekOffsetsNearTheTypeLimits)
{
    // Adding the base position to the offset before range-checking it would be signed
    // overflow rather than the -1 the protocol asks for.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "12345";

    using off_type = std::streambuf::off_type;
    const off_type max = std::numeric_limits<off_type>::max();
    const off_type min = std::numeric_limits<off_type>::lowest();

    for (const auto dir : {std::ios_base::beg, std::ios_base::cur, std::ios_base::end})
    {
        EXPECT_EQ(sbuf.pubseekoff(max, dir, std::ios_base::in), bad_pos());
        EXPECT_EQ(sbuf.pubseekoff(min, dir, std::ios_base::in), bad_pos());
    }

    // ...and the buffer is still readable from where it was.
    EXPECT_EQ(ios.tellg(), std::streampos(0));
    EXPECT_EQ(drain(ios), "12345");
}

TEST(BufferStream, SeeksNamingBothPositions)
{
    // in|out is pubseekoff()'s default argument, so refusing it outright fails the
    // plainest call a library holding a streambuf can make.  It is answerable wherever
    // the two positions coincide, which for an append-only put position is the end.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "12345";

    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::end), std::streambuf::pos_type(5));
    EXPECT_EQ(sbuf.pubseekpos(5), std::streambuf::pos_type(5));

    // Answered, not acted on: a measurement that moved the reader would need a seek
    // back, and in|out cannot provide one.
    EXPECT_EQ(ios.tellg(), std::streampos(0));

    // The rewind of a measure-then-rewind is refused on in|out, the put position being
    // unable to follow, and has to name in alone.
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::beg), bad_pos());
    EXPECT_EQ(sbuf.pubseekoff(-5, std::ios_base::end), bad_pos());
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::beg, std::ios_base::in), std::streambuf::pos_type(0));

    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::cur), bad_pos()); // no one position

    // A stray mode bit is not a reason to refuse a seek this class can answer.
    EXPECT_EQ(sbuf.pubseekpos(0, std::ios_base::in | std::ios_base::binary),
              std::streambuf::pos_type(0));
    EXPECT_EQ(drain(ios), "12345");
}

TEST(BufferStream, SeeksThatMustSucceed)
{
    // Positive siblings for the refusals above: without these, deleting the seekoff
    // override outright still passes, the base class returning -1 for everything.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "12345";

    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::cur, std::ios_base::out), std::streambuf::pos_type(5));
    EXPECT_EQ(sbuf.pubseekoff(0, std::ios_base::beg, std::ios_base::in), std::streambuf::pos_type(0));
    EXPECT_EQ(sbuf.pubseekoff(2, std::ios_base::cur, std::ios_base::in), std::streambuf::pos_type(2));
    EXPECT_EQ(sbuf.pubseekoff(-1, std::ios_base::end, std::ios_base::in), std::streambuf::pos_type(4));
    EXPECT_EQ(sbuf.pubseekpos(3, std::ios_base::in), std::streambuf::pos_type(3));
    EXPECT_EQ(sbuf.pubseekoff(5, std::ios_base::beg, std::ios_base::out), std::streambuf::pos_type(5));
}

TEST(BufferStream, RejectsNegativeCounts)
{
    // A negative streamsize cast straight to size_t asks the buffer for ~0 bytes.
    // The negative counts are the point of the test, hence the Coverity waivers.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStream sbuf(buf);
    std::iostream ios(&sbuf);

    // coverity[NEGATIVE_RETURNS]
    EXPECT_EQ(sbuf.sputn("abc", -1), 0);
    EXPECT_EQ(buf.size(), 0U);

    // With something there to read: on an empty buffer the count comes out 0 whether
    // the guard is there or not, and what it stands between is sgetn(got, -1) and a
    // buf.size() memcpy into a four-byte array.
    ios << "0123456789";
    ios.flush();

    std::array<char, 4> got{};
    // coverity[NEGATIVE_RETURNS]
    EXPECT_EQ(sbuf.sgetn(got.data(), -1), 0);
    EXPECT_EQ(ios.tellg(), std::streampos(0)) << "a refused read must not consume";
}

TEST(BufferStream, OverflowAtEofReportsSuccess)
{
    // overflow(eof()) writes nothing and must not report failure for it.  sputc() only
    // ever reaches overflow() with a converted 0..255, so the call has to be direct.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    OverflowProbe sbuf(buf);

    EXPECT_NE(sbuf.overflow(std::streambuf::traits_type::eof()), std::streambuf::traits_type::eof());
    EXPECT_EQ(buf.size(), 0U) << "nothing was asked for, so nothing may be written";

    EXPECT_NE(sbuf.sputc('a'), std::streambuf::traits_type::eof());
    EXPECT_EQ(buf_to_string(buf), "a");
}

TEST(BufferStream, FlushSettlesTheGetArea)
{
    // flush() reaches sync(), which folds the get area back in and drops it: the
    // supported point at which to hand the Buffer back to its owner.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    GetAreaProbe sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "abcdef";
    ASSERT_EQ(ios.get(), 'a');
    ASSERT_NE(sbuf.gptr(), nullptr);

    ios.flush();
    EXPECT_EQ(sbuf.gptr(), nullptr) << "sync() must drop the area";
    EXPECT_EQ(ios.tellg(), std::streampos(1)) << "without losing what it had delivered";
    EXPECT_EQ(drain(ios), "bcdef");
}

TEST(BufferStream, ARefusedSeekLeavesTheReadAlone)
{
    // seekoff() settles the answer before it disturbs anything, so a seek it cannot
    // satisfy does not cost the reader the area it was being served from.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    GetAreaProbe sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "abcdef";
    ASSERT_EQ(ios.get(), 'a');
    ASSERT_NE(sbuf.gptr(), nullptr);

    EXPECT_EQ(sbuf.pubseekoff(99, std::ios_base::beg, std::ios_base::in), bad_pos());
    EXPECT_NE(sbuf.gptr(), nullptr) << "a refused seek must not drop the area";
    EXPECT_EQ(drain(ios), "bcdef");
}

TEST(BufferStream, ReadCursorCannotBeForked)
{
    // Copying would give a second streambuf its own position over one Buffer.
    static_assert(!std::is_copy_constructible_v<BufferStream>);
    static_assert(!std::is_move_constructible_v<BufferStream>);
    static_assert(!std::is_copy_assignable_v<BufferStream>);
}

TEST(BufferStream, InOutWrapperReadsBackWhatItWrote)
{
    BufferAllocated buf(4, BufAllocFlags::GROW);
    BufferStreamInOut ios(buf);

    ios << "This is a test of the " << 2014 << " zombie invasion.\n";

    const std::string body("This is a test of the 2014 zombie invasion.\n");
    EXPECT_EQ(ios.tellp(), std::streampos(body.size()));
    EXPECT_EQ(drain(ios), body);
    EXPECT_EQ(buf_to_string(buf), body);
}

TEST(BufferStream, ReadsBackAPreFilledBuffer)
{
    // Nothing goes in through the stream: the read position starts at what the owner
    // has already put there, which is the whole buffer.
    BufferAllocated buf(64, BufAllocFlags::GROW);
    const std::string body("hello world");
    buf.write(body.c_str(), body.size());

    BufferStreamInOut ios(buf);
    // Coverity's basic_ios model nulls rdbuf() whatever streambuf the constructor was
    // handed, hence the waiver.
    // coverity[FORWARD_NULL]
    EXPECT_EQ(ios.rdbuf()->in_avail(), static_cast<std::streamsize>(body.size()));
    EXPECT_EQ(ios.tellg(), std::streampos(0));
    EXPECT_EQ(ios.tellp(), std::streampos(body.size()));
    EXPECT_EQ(drain(ios), body);
    EXPECT_EQ(buf_to_string(buf), body);

    // The tally counted from a buffer that was not empty, so a write still appends to
    // the end of it and reads back from where the last one stopped.
    ios << '!';
    EXPECT_EQ(drain(ios), "!");
    EXPECT_EQ(buf_to_string(buf), body + "!");
}

TEST(BufferStream, PutbackDivergenceFromStringbuf)
{
    // Documented divergence: stringbuf overwrites its buffer on a mismatched putback,
    // this refuses, the Buffer being the owner's.
    std::stringstream sstr("abc");
    ASSERT_EQ(sstr.get(), 'a');
    sstr.putback('Z');
    EXPECT_TRUE(sstr.good()) << "stringbuf is expected to accept and overwrite";

    BufferAllocated buf(16, BufAllocFlags::GROW);
    BufferStreamInOut ios(buf);
    ios << "abc";
    ASSERT_EQ(ios.get(), 'a');
    ios.putback('Z');
    EXPECT_TRUE(ios.fail());
    EXPECT_EQ(buf_to_string(buf), "abc") << "a read path must not rewrite the buffer";
}

TEST(BufferStream, UnderflowPublishesAGetArea)
{
    // [streambuf.virt.get]: underflow() returns traits::to_int_type(*gptr()), so the
    // character it reports has to be sitting at gptr() when it returns.
    BufferAllocated buf(16, BufAllocFlags::GROW);
    GetAreaProbe sbuf(buf);
    std::iostream ios(&sbuf);

    ios << "abcdef";

    ASSERT_EQ(sbuf.underflow(), 'a');
    ASSERT_NE(sbuf.gptr(), nullptr) << "no get area: istreambuf_iterator would spin";
    // codechecker_false_positive [infer-nullptr-dereference] the ASSERT_NE above returns on null
    EXPECT_EQ(*sbuf.gptr(), 'a');
    EXPECT_EQ(sbuf.egptr() - sbuf.gptr(), 6) << "the area must span the rest of the buffer";

    // And it survives being read down to nothing.
    EXPECT_EQ(drain(ios), "abcdef");
    EXPECT_EQ(sbuf.underflow(), std::streambuf::traits_type::eof());
}

/// PROPERTY: for any content of two or more bytes read partway through a published get area, an out-of-range get-only seek from cur leaves the get area in place.
RC_GTEST_PROP(BufferStream, AFailedRelativeSeekKeepsTheGetArea, ())
{
    using off_type = std::streambuf::off_type;
    const auto head = *rc::gen::arbitrary<char>().as("first byte");
    const auto rest = *rc::gen::nonEmpty(rc::gen::arbitrary<std::string>()).as("remaining bytes");
    const std::string content = head + rest;
    const auto consumed = *rc::gen::oneOf(rc::gen::just<size_t>(1),
                                          rc::gen::just(content.size() - 1),
                                          rc::gen::inRange<size_t>(1, content.size()))
                               .as("bytes read through the get area");
    const auto ahead = static_cast<off_type>(content.size() - consumed);
    const auto behind = static_cast<off_type>(consumed);
    const auto offset = *rc::gen::oneOf(rc::gen::just(ahead + 1),
                                        rc::gen::just(-behind - 1),
                                        rc::gen::inRange<off_type>(ahead + 1, ahead + 64),
                                        rc::gen::inRange<off_type>(-behind - 64, -behind))
                             .as("out-of-range offset from cur");

    BufferAllocated buf(content.size(), BufAllocFlags::GROW);
    buf.write(content.data(), content.size());
    GetAreaProbe sbuf(buf);
    for (size_t i = 0; i < consumed; ++i)
    {
        sbuf.sbumpc();
    }
    const char *const before_g = sbuf.gptr();
    const char *const before_e = sbuf.egptr();

    const bool refused = sbuf.pubseekoff(offset, std::ios_base::cur, std::ios_base::in) == bad_pos();
    RC_ASSERT(refused);

    // Not gptr() inside RC_ASSERT: its expansion would dereference the null char *.
    const bool area_kept = sbuf.gptr() == before_g && sbuf.egptr() == before_e;
    RC_ASSERT(area_kept);
}

//! Small, so that getline, ignore and >> find the delimiters they scan for.
constexpr std::string_view stream_alphabet("ab \n7-\xff");

//! The system under test: a BufferStreamInOut over a Buffer that starts out holding
//! the property's initial content.
struct FilledStream
{
    //! @param content what the Buffer holds before the first command.
    explicit FilledStream(const std::string &content)
        : buf(filled(content))
    {
    }

    //! @return a growable Buffer holding exactly @p content.
    static BufferAllocated filled(const std::string &content)
    {
        BufferAllocated buf(content.size(), BufAllocFlags::GROW);
        buf.write(content.data(), content.size());
        return buf;
    }

    BufferAllocated buf;
    BufferStreamInOut stream{buf};
};

//! The reference state: what a std::stringstream(in|out|app) holds, where it reads
//! from, and its iostate.
struct StringstreamModel
{
    std::string content;
    std::streamoff read_pos = 0;
    std::ios_base::iostate state = std::ios_base::goodbit;

    //! @return a std::stringstream rebuilt in this state.
    std::stringstream reference() const
    {
        std::stringstream ref(content, std::ios_base::in | std::ios_base::out | std::ios_base::app);
        ref.seekg(read_pos); // before setstate(): seekg() does nothing on a failed stream
        ref.setstate(state);
        return ref;
    }

    //! @return the state @p ref is in.
    static StringstreamModel snapshot(const std::stringstream &ref)
    {
        const std::streamoff position = ref.rdbuf()->pubseekoff(0, std::ios_base::cur, std::ios_base::in);
        return {.content = ref.str(), .read_pos = position, .state = ref.rdstate()};
    }
};

//! The reference is rebuilt with gcount() 0, so only an operation that sets gcount() can be compared on it.
enum class Gcount : std::uint8_t
{
    SET,     //!< The operation sets gcount(), so the two are compared.
    CARRIED, //!< gcount() is left from an earlier operation and not compared.
};

//! A command run on the BufferStreamInOut and the std::stringstream reference alike.
using BothCommand = rc::state::Command<StringstreamModel, FilledStream>;

//! A command run on both streams, whose result, rdstate() and, where the operation
//! sets it, gcount() must agree.
//! @tparam Observed what the operation returns for comparison.
//! @tparam gcount whether the operation sets gcount().
template <typename Observed, Gcount gcount>
struct BothOperation : BothCommand
{
    //! Advances the model by running the operation on a reference rebuilt from it.
    void apply(StringstreamModel &model) const final
    {
        auto ref = model.reference();
        exec(ref, model);
        model = StringstreamModel::snapshot(ref);
    }

    //! Runs the operation on both streams from the model's state and asserts they agree.
    void run(const StringstreamModel &model, FilledStream &sut) const final
    {
        auto ref = model.reference();
        const Observed expected = exec(ref, model);
        const Observed got = exec(sut.stream, model);
        RC_ASSERT(got == expected);
        RC_ASSERT(sut.stream.rdstate() == ref.rdstate());
        RC_ASSERT(gcount == Gcount::CARRIED || sut.stream.gcount() == ref.gcount());
    }

    //! Performs the operation on @p stream.
    //! @param stream the stream under test or the reference.
    //! @param before the model state the operation starts from.
    //! @return what the operation observed.
    virtual Observed exec(std::iostream &stream, const StringstreamModel &before) const = 0;
};

//! write() of generated bytes from the stream alphabet.
struct BothWrite final : BothOperation<std::monostate, Gcount::CARRIED>
{
    std::string bytes = *rc::gen::container<std::string>(rc::gen::elementOf(stream_alphabet));

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "write ";
        rc::show(bytes, out);
    }
};

//! put() of one generated byte.
struct BothPut final : BothOperation<std::monostate, Gcount::CARRIED>
{
    char byte = *rc::gen::elementOf(stream_alphabet);

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.put(byte);
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "put ";
        rc::show(byte, out);
    }
};

//! Formatted insertion of a generated int.
struct BothInsertInt final : BothOperation<std::monostate, Gcount::CARRIED>
{
    int value = *rc::gen::arbitrary<int>();

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream << value;
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "<< " << value;
    }
};

//! clear(); drawn less often than the rest, so that failed states last.
struct BothClear final : BothOperation<std::monostate, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.clear();
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "clear()";
    }
};

//! flush().
struct BothFlush final : BothOperation<std::monostate, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.flush();
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "flush()";
    }
};

//! get(), comparing the character or EOF it returns.
struct BothGet final : BothOperation<int, Gcount::SET>
{
    //! @copybrief BothOperation::exec
    int exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        return stream.get();
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "get()";
    }
};

//! peek().
struct BothPeek final : BothOperation<int, Gcount::SET>
{
    //! @copybrief BothOperation::exec
    int exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        return stream.peek();
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "peek()";
    }
};

//! read() of up to 11 bytes, comparing the buffer it fills.
struct BothRead final : BothOperation<std::string, Gcount::SET>
{
    std::streamsize count = *rc::gen::inRange<std::streamsize>(0, 12);

    //! @copybrief BothOperation::exec
    std::string exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        std::string bytes(static_cast<size_t>(count), '\0');
        stream.read(bytes.data(), count);
        return bytes;
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "read(" << count << ")";
    }
};

//! ignore() of a small count, or of everything.
struct BothIgnore final : BothOperation<std::monostate, Gcount::SET>
{
    std::streamsize count = *rc::gen::oneOf(rc::gen::inRange<std::streamsize>(0, 12),
                                            rc::gen::just(std::numeric_limits<std::streamsize>::max()));

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.ignore(count);
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "ignore(" << count << ")";
    }
};

//! ignore() up to a count or a delimiter from the stream alphabet.
struct BothIgnoreDelim final : BothOperation<std::monostate, Gcount::SET>
{
    std::streamsize count = *rc::gen::inRange<std::streamsize>(0, 64);
    char delim = *rc::gen::elementOf(stream_alphabet);

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.ignore(count, std::char_traits<char>::to_int_type(delim));
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "ignore(" << count << ", ";
        rc::show(delim, out);
        out << ")";
    }
};

//! std::getline() up to a delimiter from the stream alphabet.  It is not
//! istream::getline and leaves gcount() alone.
struct BothGetline final : BothOperation<std::string, Gcount::CARRIED>
{
    char delim = *rc::gen::elementOf(stream_alphabet);

    //! @copybrief BothOperation::exec
    std::string exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        std::string line;
        std::getline(stream, line, delim);
        return line;
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "getline(";
        rc::show(delim, out);
        out << ")";
    }
};

//! Formatted extraction of a whitespace-delimited word.
struct BothExtractWord final : BothOperation<std::string, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::string exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        std::string word;
        stream >> word;
        return word;
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << ">> std::string";
    }
};

//! Formatted extraction of an int.
struct BothExtractInt final : BothOperation<int, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    int exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        int value = 0;
        stream >> value;
        return value;
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << ">> int";
    }
};

//! Up to 11 bytes through a std::istreambuf_iterator, which reads the get area directly.
struct BothIstreambufWalk final : BothOperation<std::string, Gcount::CARRIED>
{
    size_t count = *rc::gen::inRange<size_t>(0, 12);

    //! @copybrief BothOperation::exec
    std::string exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        std::string taken;
        for (std::istreambuf_iterator<char> iter(stream); taken.size() < count && iter != std::istreambuf_iterator<char>(); ++iter)
        {
            taken.push_back(*iter);
        }
        return taken;
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "istreambuf_iterator takes up to " << count;
    }
};

//! seekg() from beg, cur or end, by a small or a 16-bit offset.
struct BothSeekg final : BothOperation<std::monostate, Gcount::CARRIED>
{
    std::streamoff offset = *rc::gen::oneOf(rc::gen::inRange<std::streamoff>(-3, 4),
                                            rc::gen::cast<std::streamoff>(rc::gen::arbitrary<std::int16_t>()));
    std::ios_base::seekdir dir = *rc::gen::element(std::ios_base::beg, std::ios_base::cur, std::ios_base::end);

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.seekg(offset, dir);
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "seekg(" << offset << ", ";
        if (dir == std::ios_base::beg)
        {
            out << "beg";
        }
        else if (dir == std::ios_base::cur)
        {
            out << "cur";
        }
        else
        {
            out << "end";
        }
        out << ")";
    }
};

//! tellg().
struct BothTellg final : BothOperation<std::streamoff, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::streamoff exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        return stream.tellg();
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "tellg()";
    }
};

//! tellp().
struct BothTellp final : BothOperation<std::streamoff, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::streamoff exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        return stream.tellp();
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "tellp()";
    }
};

//! unget().
struct BothUnget final : BothOperation<std::monostate, Gcount::CARRIED>
{
    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel & /*before*/) const override
    {
        stream.unget();
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "unget()";
    }
};

//! putback() of the byte before the read position, which is all it is given:
//! std::stringbuf overwrites on a mismatched putback.
struct BothPutbackMatching final : BothOperation<std::monostate, Gcount::CARRIED>
{
    char at_start = *rc::gen::elementOf(stream_alphabet);

    //! @copybrief BothOperation::exec
    std::monostate exec(std::iostream &stream, const StringstreamModel &before) const override
    {
        stream.putback(before.read_pos > 0 ? before.content.at(static_cast<size_t>(before.read_pos - 1)) : at_start);
        return {};
    }

    //! Prints the operation in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "putback(the byte before the read position, or ";
        rc::show(at_start, out);
        out << " at the start)";
    }
};

/// PROPERTY: for any initial content and any sequence of appends, flushes, clears, reads, extractions, get-side seeks, tellg/tellp, unget and putback of the preceding byte, every operation on a BufferStreamInOut returns what std::stringstream(content, in|out|app) returns from the same state and leaves the same rdstate(), and an unformatted read the same gcount().
RC_GTEST_PROP(BufferStream, ReadsAgreeWithStringstream, (const std::string &content))
{
    FilledStream sut(content);
    rc::state::check(StringstreamModel{.content = content},
                     sut,
                     [](const StringstreamModel &model)
                     {
                         const auto others = rc::state::gen::execOneOfWithArgs<BothWrite,
                                                                               BothPut,
                                                                               BothInsertInt,
                                                                               BothFlush,
                                                                               BothGet,
                                                                               BothPeek,
                                                                               BothRead,
                                                                               BothIgnore,
                                                                               BothIgnoreDelim,
                                                                               BothGetline,
                                                                               BothExtractWord,
                                                                               BothExtractInt,
                                                                               BothIstreambufWalk,
                                                                               BothSeekg,
                                                                               BothTellg,
                                                                               BothTellp,
                                                                               BothUnget,
                                                                               BothPutbackMatching>()(model);
                         const auto clear = rc::state::gen::execOneOfWithArgs<BothClear>()(model);
                         return rc::gen::weightedOneOf<std::shared_ptr<const BothCommand>>({{4, others}, {1, clear}});
                     });
}

//! Positions are absolute indices into everything ever written, consumed by the owner or not.
struct OwnedStreamModel
{
    std::string written;
    size_t owner_front = 0;
    size_t read_pos = 0;

    //! @return the bytes the Buffer still holds.
    std::streamoff live() const
    {
        return static_cast<std::streamoff>(written.size() - owner_front);
    }

    //! @return the bytes from the owner's front to the read position: what tellg() reports.
    std::streamoff behind() const
    {
        return static_cast<std::streamoff>(read_pos - owner_front);
    }

    //! @return the bytes left to read.
    std::streamoff ahead() const
    {
        return static_cast<std::streamoff>(written.size() - read_pos);
    }
};

//! A command on a BufferStreamInOut whose Buffer's owner may consume from the front.
using OwnedCommand = rc::state::Command<OwnedStreamModel, FilledStream>;

//! write() of generated bytes.
struct OwnedWrite final : OwnedCommand
{
    std::string bytes = *rc::gen::arbitrary<std::string>();

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        model.written += bytes;
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel & /*model*/, FilledStream &sut) const override
    {
        sut.stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        sut.stream.clear();
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "write ";
        rc::show(bytes, out);
    }
};

//! Hands the Buffer back with pubsync(), then the owner consumes from the front.
struct OwnerAdvance final : OwnedCommand
{
    size_t count;

    //! @param model the state the count is drawn against: up to everything live.
    explicit OwnerAdvance(const OwnedStreamModel &model)
        : count(*rc::gen::oneOf(rc::gen::just(static_cast<size_t>(model.live())),
                                rc::gen::inRange<size_t>(0, static_cast<size_t>(model.live()) + 1)))
    {
    }

    //! Rejects a count past what is live, which shrinking can leave behind.
    void checkPreconditions(const OwnedStreamModel &model) const override
    {
        RC_PRE(static_cast<std::streamoff>(count) <= model.live());
    }

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        model.owner_front += count;
        model.read_pos = std::max(model.read_pos, model.owner_front);
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel & /*model*/, FilledStream &sut) const override
    {
        sut.stream.rdbuf()->pubsync();
        sut.buf.advance(count);
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "pubsync(), then the owner advances " << count;
    }
};

//! get(): the next byte, or EOF at the end.
struct OwnedGet final : OwnedCommand
{
    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        model.read_pos = std::min(model.read_pos + 1, model.written.size());
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        const int expected = model.read_pos < model.written.size()
                                 ? std::char_traits<char>::to_int_type(model.written.at(model.read_pos))
                                 : std::char_traits<char>::eof();
        const int got = sut.stream.get();
        sut.stream.clear();
        RC_ASSERT(got == expected);
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "get()";
    }
};

//! read() of up to 15 bytes.
struct OwnedRead final : OwnedCommand
{
    size_t count = *rc::gen::inRange<size_t>(0, 16);

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        model.read_pos = std::min(model.read_pos + count, model.written.size());
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        std::string got(count, '\0');
        sut.stream.read(got.data(), static_cast<std::streamsize>(count));
        got.resize(static_cast<size_t>(sut.stream.gcount()));
        sut.stream.clear();
        RC_ASSERT(got == model.written.substr(model.read_pos, count));
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "read(" << count << ")";
    }
};

//! seekg() from beg, which counts from the owner's front.
struct OwnedSeekgBeg final : OwnedCommand
{
    std::streamoff target;

    //! @param model the state the target is drawn against, each edge and one past it included.
    explicit OwnedSeekgBeg(const OwnedStreamModel &model)
        : target(*rc::gen::oneOf(rc::gen::just(model.live()),
                                 rc::gen::just(model.live() + 1),
                                 rc::gen::just<std::streamoff>(-1),
                                 rc::gen::inRange<std::streamoff>(0, model.live() + 1)))
    {
    }

    //! @return whether the target lies in the live region, between the owner's front and the end.
    bool accepts(const OwnedStreamModel &model) const
    {
        return target >= 0 && target <= model.live();
    }

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        if (accepts(model))
        {
            model.read_pos = model.owner_front + static_cast<size_t>(target);
        }
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        sut.stream.seekg(target, std::ios_base::beg);
        const bool accepted = !sut.stream.fail();
        sut.stream.clear();
        RC_ASSERT(accepted == accepts(model));
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "seekg(" << target << ", beg)";
    }
};

//! seekg() from end.
struct OwnedSeekgEnd final : OwnedCommand
{
    std::streamoff target;

    //! @param model the state the target is drawn against, each edge and one past it included.
    explicit OwnedSeekgEnd(const OwnedStreamModel &model)
        : target(*rc::gen::oneOf(rc::gen::just(-model.live()),
                                 rc::gen::just(-model.live() - 1),
                                 rc::gen::just<std::streamoff>(1),
                                 rc::gen::inRange<std::streamoff>(-model.live(), 1)))
    {
    }

    //! @return whether the target lies in the live region, between the owner's front and the end.
    bool accepts(const OwnedStreamModel &model) const
    {
        return target <= 0 && target >= -model.live();
    }

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        if (accepts(model))
        {
            model.read_pos = static_cast<size_t>(static_cast<std::streamoff>(model.written.size()) + target);
        }
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        sut.stream.seekg(target, std::ios_base::end);
        const bool accepted = !sut.stream.fail();
        sut.stream.clear();
        RC_ASSERT(accepted == accepts(model));
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "seekg(" << target << ", end)";
    }
};

//! seekg() from cur.
struct OwnedSeekgCur final : OwnedCommand
{
    std::streamoff offset;

    //! @param model the state the offset is drawn against, each edge and one past it included.
    explicit OwnedSeekgCur(const OwnedStreamModel &model)
        : offset(*rc::gen::oneOf(rc::gen::just(-model.behind()),
                                 rc::gen::just(-model.behind() - 1),
                                 rc::gen::just(model.ahead()),
                                 rc::gen::just(model.ahead() + 1),
                                 rc::gen::inRange<std::streamoff>(-model.behind(), model.ahead() + 1)))
    {
    }

    //! @return whether the target lies in the live region, between the owner's front and the end.
    bool accepts(const OwnedStreamModel &model) const
    {
        return offset >= -model.behind() && offset <= model.ahead();
    }

    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        if (accepts(model))
        {
            model.read_pos = static_cast<size_t>(static_cast<std::streamoff>(model.read_pos) + offset);
        }
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        sut.stream.seekg(offset, std::ios_base::cur);
        const bool accepted = !sut.stream.fail();
        sut.stream.clear();
        RC_ASSERT(accepted == accepts(model));
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "seekg(" << offset << ", cur)";
    }
};

//! tellg(), which counts from the owner's front.
struct OwnedTellg final : OwnedCommand
{
    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        const std::streamoff got = sut.stream.tellg();
        sut.stream.clear();
        RC_ASSERT(got == model.behind());
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "tellg()";
    }
};

//! unget(), refused at the owner's front.
struct OwnedUnget final : OwnedCommand
{
    //! Moves the model as the command moves the stream.
    void apply(OwnedStreamModel &model) const override
    {
        if (model.read_pos > model.owner_front)
        {
            --model.read_pos;
        }
    }

    //! Runs the command and asserts what it observes against the model.
    void run(const OwnedStreamModel &model, FilledStream &sut) const override
    {
        sut.stream.unget();
        const bool stepped_back = !sut.stream.fail();
        sut.stream.clear();
        RC_ASSERT(stepped_back == (model.read_pos > model.owner_front));
    }

    //! Prints the command in a counterexample.
    void show(std::ostream &out) const override
    {
        out << "unget()";
    }
};

/// PROPERTY: for any initial content and any sequence of writes, get(), read(), get-side seeks, tellg(), unget() and owner advance() calls made after a sync, every observation - the bytes read, tellg(), and whether a seek or unget succeeds - matches a model of absolute positions in everything written, in which an owner consuming the front moves only the front.
RC_GTEST_PROP(BufferStream, OwnerConsumingFrontKeepsTheUndeliveredTail, (const std::string &content))
{
    FilledStream sut(content);
    rc::state::check(OwnedStreamModel{.written = content},
                     sut,
                     rc::state::gen::execOneOfWithArgs<OwnedWrite,
                                                       OwnerAdvance,
                                                       OwnedGet,
                                                       OwnedRead,
                                                       OwnedSeekgBeg,
                                                       OwnedSeekgEnd,
                                                       OwnedSeekgCur,
                                                       OwnedTellg,
                                                       OwnedUnget>());
}
