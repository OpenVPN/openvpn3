//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// API for SSL implementations

#ifndef OPENVPN_SSL_SSLAPI_H
#define OPENVPN_SSL_SSLAPI_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  class SSLAPI : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<SSLAPI> Ptr;

    virtual void start_handshake() = 0;
    virtual ssize_t write_cleartext_unbuffered(const void *data, const size_t size) = 0;
    virtual ssize_t read_cleartext(void *data, const size_t capacity) = 0;
    virtual bool read_cleartext_ready() const = 0;
    virtual void write_ciphertext(const BufferPtr& buf) = 0;
    virtual bool read_ciphertext_ready() const = 0;
    virtual BufferPtr read_ciphertext() = 0;
    virtual std::string ssl_handshake_details() const = 0;
  };

  class SSLFactoryAPI : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<SSLFactoryAPI> Ptr;

    // create a new SSLAPI instance
    virtual SSLAPI::Ptr ssl() = 0;

    // like ssl() above but verify hostname against cert CommonName and/or SubjectAltName
    virtual SSLAPI::Ptr ssl(const std::string& hostname) = 0;

    // client or server?
    virtual const Mode& mode() const = 0;
  };
}

#endif
