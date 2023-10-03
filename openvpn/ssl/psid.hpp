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

// A 64-bit session ID, used by ProtoContext.

#ifndef OPENVPN_SSL_PSID_H
#define OPENVPN_SSL_PSID_H

#include <string>
#include <cstring>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/memneq.hpp>

namespace openvpn {

class ProtoSessionID
{
  public:
    enum
    {
        SIZE = 8
    };

    constexpr ProtoSessionID()
        : defined_(false), id_{}
    {
    }

    void reset()
    {
        defined_ = false;
        std::memset(id_, 0, SIZE);
    }

    template <typename BufType> // so it can take a Buffer or a ConstBuffer
    explicit ProtoSessionID(BufType &buf)
    {
        buf.read(id_, SIZE);
        defined_ = true;
    }

    template <typename PRNG_TYPE>
    void randomize(PRNG_TYPE &prng)
    {
        prng.assert_crypto();
        prng.rand_bytes(id_, SIZE);
        defined_ = true;
    }

    template <typename BufType> // so it can take a Buffer or a ConstBuffer
    void read(BufType &buf)
    {
        buf.read(id_, SIZE);
        defined_ = true;
    }

    void write(Buffer &buf) const
    {
        buf.write(id_, SIZE);
    }

    void prepend(Buffer &buf) const
    {
        buf.prepend(id_, SIZE);
    }

    // returned buffer is only valid for *this lifetime
    const Buffer get_buf() const
    {
        if (defined_)
        {
            return PsidBuf(const_cast<Buffer::type>(id_));
        }
        return Buffer();
    }

    constexpr bool defined() const
    {
        return defined_;
    }

    bool match(const ProtoSessionID &other) const
    {
        return defined_ && other.defined_ && !crypto::memneq(id_, other.id_, SIZE);
    }

    std::string str() const
    {
        return render_hex(id_, SIZE);
    }

  private:
    // access protected ctor to use Buffer w/o memcpy
    struct PsidBuf : Buffer
    {
        // T* data, const size_t offset, const size_t size, const size_t capacity
        PsidBuf(typename Buffer::type id)
            : Buffer(id, 0, SIZE, SIZE)
        {
        }
    };

    bool defined_;
    unsigned char id_[SIZE];
};
} // namespace openvpn

#endif // OPENVPN_SSL_PSID_H
