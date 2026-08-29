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

#ifndef OPENVPN_BUFFER_BUFSTREAM_H
#define OPENVPN_BUFFER_BUFSTREAM_H

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ios>
#include <istream>
#include <ostream>
#include <streambuf>

#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

/**
 * Streambuf over a Buffer: writes append to it, reads replay what it holds.
 *
 * The read position is kept here rather than by advancing Buffer::read(), which would
 * consume the owner's bytes.  It is a count still to deliver, measured back from the
 * end, so an owner consuming from the front does not shift what is left to read.  The
 * end moves with direct writes too, though: after n bytes are written to the Buffer
 * other than through this streambuf, the reader still delivers only as many bytes as
 * it owed, counted back from the new end, so it skips the first n of what it owed
 * followed by what was written.  A reset_size() and refill likewise leaves the
 * position inside the new body rather than at its start.  seekg() puts it back.
 *
 * underflow() publishes a get area over the Buffer's storage, as the protocol requires:
 * libstdc++ advances a std::istreambuf_iterator by looping on egptr() - gptr(), which
 * spins forever without one.  Every call reaching this class drops it again, so a write
 * through here cannot leave it dangling.  The base class serves reads out of it without
 * calling here, though, so an owner touching the Buffer mid-read hands the reader stale
 * bytes, or freed storage if it reallocated.  ASAN does not see that read, which
 * happens inside libstdc++.  Call rdbuf()->pubsync() before touching the Buffer, or
 * clear() and seekg() after: flush() and seekg() do nothing while the stream has
 * failed, as it has once a read reaches the end.
 */
class BufferStream : public std::streambuf
{
  public:
    //! @param buffer streamed over in place, so it must outlive this streambuf.  What
    //!        it already holds is there to be read.
    explicit BufferStream(Buffer &buffer)
        : buf(buffer),
          unread(buffer.size())
    {
    }

    /**
     * @name Neither copyable nor movable
     *
     * Either would fork the read position over one Buffer, and the two streambufs
     * would then interleave the same bytes.
     */
    ///@{
    BufferStream(const BufferStream &) = delete;
    BufferStream &operator=(const BufferStream &) = delete;
    BufferStream(BufferStream &&) = delete;
    BufferStream &operator=(BufferStream &&) = delete;
    ///@}

    //! Releases nothing: the Buffer stays its owner's.
    ~BufferStream() override = default;

  protected:
    // input
    //! @return bytes readable now; 0 rather than -1 at the end, a later write being
    //!         free to add more.
    std::streamsize showmanyc() override
    {
        resync();
        return static_cast<std::streamsize>(avail());
    }

    //! Bulk read of at most @p n bytes into @p dest.
    //! @return the count copied, short of @p n once the buffer runs out.
    std::streamsize xsgetn(char *dest, std::streamsize n) override
    {
        resync();
        const size_t have = avail();
        const size_t count = n > 0 ? std::min(have, static_cast<size_t>(n)) : 0;
        if (count == 0)
        {
            return 0; // c_data() may be null, and memcpy will not take that even for 0
        }
        std::memcpy(dest, buf.c_index(gpos()), count);
        // Off what the buffer holds, not off a count still owing bytes the owner has
        // since eaten from the front: nothing here resyncs the tally afterwards.
        unread = have - count;
        return static_cast<std::streamsize>(count);
    }

    //! @return the byte at the read position, left unconsumed; EOF at the end.
    int underflow() override
    {
        resync();
        const size_t left = avail();
        if (left == 0)
        {
            return EOF;
        }
        char *const base = reinterpret_cast<char *>(buf.data());
        setg(base, base + (buf.size() - left), base + buf.size());
        // Through unsigned char: a 0xFF byte returned as a signed one is EOF.
        return static_cast<unsigned char>(*gptr());
    }

    /**
     * Step the read position back one byte.
     *
     * @param expected the byte the caller expects there, EOF to take whatever is.
     * @return that byte; EOF at the start of the buffer, or when @p expected is not
     *         what the buffer holds.
     *
     * Unlike std::stringbuf, a mismatched @p expected is refused rather than written
     * over the buffer, which is the owner's.
     */
    int pbackfail(int expected) override
    {
        resync();
        const size_t pos = gpos();
        if (pos == 0)
        {
            return EOF;
        }
        const unsigned char prev = *buf.c_index(pos - 1);
        if (expected != EOF && static_cast<unsigned char>(expected) != prev)
        {
            return EOF;
        }
        ++unread;
        return prev;
    }

    /**
     * Report a position, and move the read one.
     *
     * @return the resulting position, or -1 for a request that cannot be satisfied.
     *
     * Writes always append, so the put position stays at the end: @a out may be asked
     * where it is and told to stay there, which keeps the save/restore idiom working,
     * but not moved.
     *
     * @a in and @a out together, pubseekoff()'s default, are answerable only at the end,
     * where the two positions coincide, and the read position is left where it was.
     * pubseekoff(0, end) therefore measures the buffer without costing a reader its
     * place.  A seek from cur naming both fails even there, as std::stringbuf's does:
     * there is no one position for it to be relative to.  Any other target fails, the
     * rewind of a measure-then-rewind included: a rewind has to name @a in alone, as
     * seekg() does.  Moving only the read position would report a put position the next
     * write ignores, appending where a caller rewinding a std::stringbuf expects to
     * overwrite.
     *
     * The end is the Buffer's own, so an owner consuming from the front moves the put
     * position back and leaves a mark saved beforehand out of range.  The restoring seek
     * then fails, and its failbit silences the writes after it.
     *
     * A seek that fails costs the reader neither its position nor its get area.
     */
    pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override
    {
        const bool get = (which & std::ios_base::in) == std::ios_base::in;
        const bool put = (which & std::ios_base::out) == std::ios_base::out;
        if (!get && !put)
        {
            return bad_pos();
        }

        const auto end = static_cast<off_type>(buf.size());

        off_type base = 0;
        if (dir == std::ios_base::end)
        {
            base = end;
        }
        else if (dir == std::ios_base::cur)
        {
            if (get && put)
            {
                return bad_pos(); // no one position to be relative to
            }
            base = get ? static_cast<off_type>(gpos()) : end;
        }
        else if (dir != std::ios_base::beg)
        {
            return bad_pos();
        }

        // Range-checked before adding, base + off being free to overflow off_type.
        if (off < -base || off > end - base)
        {
            return bad_pos();
        }
        const off_type target = base + off;

        if (put && target != end)
        {
            return bad_pos();
        }
        if (get && !put)
        {
            resync();
            // off_type is wider than size_t on 32-bit, so the narrowing is explicit.
            unread = static_cast<size_t>(end - target);
        }
        return {target};
    }

    //! seekoff() from the start of the buffer, with the same @p which rules.
    pos_type seekpos(pos_type pos, std::ios_base::openmode which) override
    {
        return seekoff(pos, std::ios_base::beg, which);
    }

    // output
    //! Append @p n bytes of @p s.
    //! @return @p n; 0 for a negative @p n, which would otherwise reach the Buffer as
    //!         a ~0 request.  A Buffer without BufAllocFlags::GROW that cannot take
    //!         all @p n takes none of it: Buffer::write() throws, and the stream turns
    //!         that into badbit rather than a short count.
    std::streamsize xsputn(const char *s, std::streamsize n) override
    {
        if (n <= 0)
        {
            return 0;
        }
        resync();
        // streamsize is wider than size_t on 32-bit, so the narrowing is explicit.
        buf.write(s, static_cast<size_t>(n));
        unread += static_cast<size_t>(n);
        return n;
    }

    //! Append the single byte @p c.
    //! @return @p c; for EOF a value that is not it, nothing having been asked for
    //!         and so nothing having failed.
    int overflow(int c = EOF) override
    {
        if (c == EOF)
        {
            return traits_type::not_eof(c); // nothing asked for is nothing failed
        }
        resync();
        buf.push_back(static_cast<unsigned char>(c));
        ++unread;
        return c;
    }

    //! Drop the get area, so the owner may touch the Buffer; flush() and std::endl
    //! land here.
    //! @return 0, nothing here being able to fail.
    int sync() override
    {
        resync();
        return 0;
    }

  private:
    //! What the streambuf protocol wants back for a request it cannot satisfy.
    static pos_type bad_pos()
    {
        return {off_type{-1}};
    }

    //! Fold whatever the base class read through the get area back into @a unread, then
    //! drop the area: the Buffer's storage may move before the next call reaches here.
    void resync()
    {
        if (gptr() != nullptr)
        {
            unread = egptr() - gptr();
            setg(nullptr, nullptr, nullptr);
        }
    }

    //! Bytes written but not yet read back, clamped to what the buffer still holds.
    //! Reads through a published get area without dropping it, so a refused seek can
    //! measure from the read position and leave the area alone.
    size_t avail() const
    {
        const size_t owed = gptr() != nullptr ? static_cast<size_t>(egptr() - gptr()) : unread;
        return std::min(owed, buf.size());
    }

    //! The read position, derived from the end so that it survives the owner consuming
    //! from the front.
    size_t gpos() const
    {
        return buf.size() - avail();
    }

    Buffer &buf;
    size_t unread; //!< Bytes still to deliver, counted back from buf.size().
};

namespace bufstream_detail {

//! Gives the streambuf a home that outlives the stream bases referring to it.
struct Holder
{
    //! @param buffer forwarded to the housed streambuf.
    explicit Holder(Buffer &buffer)
        : sb(buffer)
    {
    }

    BufferStream sb;
};

} // namespace bufstream_detail

//! std::ostream appending to a Buffer; BufferStreamInOut to read it back as well.
class BufferStreamOut : private bufstream_detail::Holder, public std::ostream
{
  public:
    //! @param buffer everything written here is appended to.
    explicit BufferStreamOut(Buffer &buffer)
        : bufstream_detail::Holder(buffer),
          std::ostream(&sb)
    {
    }
};

//! BufferStreamOut's counterpart for reading a Buffer back, and the supported way to do
//! it: BufferStreamOut is an ostream, with no read side to ask for.
//!
//! The two halves share one iostate, so a read that fails stops the writes after it
//! until clear(): reaching the end sets eofbit and failbit as any istream does, and a
//! putback this class refuses arrives from basic_istream as badbit.
class BufferStreamInOut : private bufstream_detail::Holder, public std::iostream
{
  public:
    //! @param buffer written to, and replayed from the start.
    explicit BufferStreamInOut(Buffer &buffer)
        : bufstream_detail::Holder(buffer),
          std::iostream(&sb)
    {
    }
};

} // namespace openvpn

#endif
