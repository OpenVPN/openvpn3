//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Wrap the Apple SSL API as defined in <Security/SecureTransport.h>
// so that it can be used as the SSL layer by the OpenVPN core.

// Note that the Apple SSL API is missing some functionality (as of
// Mac OS X 10.8) that makes it difficult to use as a drop in replacement
// for OpenSSL or PolarSSL.  The biggest issue is that the API doesn't
// allow an SSL context to be built out of PEM-based certificates and
// keys.  It requires an "Identity" in the Keychain that was imported
// by the user as a PKCS#12 file.

#ifndef OPENVPN_APPLECRYPTO_SSL_SSLCTX_H
#define OPENVPN_APPLECRYPTO_SSL_SSLCTX_H

#include <string>

#include <Security/SecImportExport.h>
#include <Security/SecItem.h>
#include <Security/SecureTransport.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/mode.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/frame/memq_stream.hpp>
#include <openvpn/pki/epkibase.hpp>
#include <openvpn/applecrypto/cf/cfsec.hpp>
#include <openvpn/applecrypto/cf/error.hpp>

// An SSL Context is essentially a configuration that can be used
// to generate an arbitrary number of actual SSL connections objects.

// AppleSSLContext is an SSL Context implementation that uses the
// Mac/iOS SSL library as a backend.

namespace openvpn {

  // Represents an SSL configuration that can be used
  // to instantiate actual SSL sessions.
  class AppleSSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    OPENVPN_EXCEPTION(ssl_context_error);
    OPENVPN_EXCEPTION(ssl_ciphertext_in_overflow);

    typedef boost::intrusive_ptr<AppleSSLContext> Ptr;

    enum {
      MAX_CIPHERTEXT_IN = 64
    };

    // The data needed to construct an AppleSSLContext.
    struct Config
    {
      Config() : ssl_debug_level(0) {}

      Mode mode;
      int ssl_debug_level;
      CF::Array identity; // as returned by load_identity
      Frame::Ptr frame;

      void load_identity(const std::string& subject_match)
      {
	identity = load_identity_(subject_match);
	if (!identity())
	  OPENVPN_THROW(ssl_context_error, "AppleSSLContext: identity '" << subject_match << "' undefined");	
      }

      void load(const OptionList& opt)
      {
	// client/server
	mode = opt.exists("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// identity
	{
	  const std::string& subject_match = opt.get("identity", 1);
	  load_identity(subject_match);
	}
      }

      void set_external_pki_callback(ExternalPKIBase* external_pki_arg)
      {
      }
    };

    // Represents an actual SSL session.
    // Normally instantiated by AppleSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
      friend class AppleSSLContext;

    public:
      typedef boost::intrusive_ptr<SSL> Ptr;

      enum {
	SHOULD_RETRY = -1
      };

      void start_handshake()
      {
	SSLHandshake(ssl);
      }

      ssize_t write_cleartext_unbuffered(const void *data, const size_t size)
      {
	size_t actual = 0;
	const OSStatus status = SSLWrite(ssl, data, size, &actual);
	if (status < 0 || actual != size)
	  {
	    if (status == errSSLWouldBlock)
	      return SHOULD_RETRY;
	    else
	      throw CFException("AppleSSLContext::SSL::write_cleartext failed", status);
	  }
	else
	  return actual;
      }

      ssize_t read_cleartext(void *data, const size_t capacity)
      {
	if (!overflow)
	  {
	    size_t actual = 0;
	    const OSStatus status = SSLRead(ssl, data, capacity, &actual);
	    if (status < 0)
	      {
		if (status == errSSLWouldBlock)
		  return SHOULD_RETRY;
		else
		  throw CFException("AppleSSLContext::SSL::read_cleartext failed", status);
	      }
	    else
	      return actual;
	  }
	else
	  throw ssl_ciphertext_in_overflow();
      }

      bool write_ciphertext_ready() const {
	return !ct_in.empty();
      }

      void write_ciphertext(const BufferPtr& buf)
      {
	if (ct_in.size() < MAX_CIPHERTEXT_IN)
	  ct_in.write_buf(buf);
	else
	  overflow = true;
      }

      bool read_ciphertext_ready() const {
	return !ct_out.empty();
      }

      BufferPtr read_ciphertext()
      {
	return ct_out.read_buf();
      }

      std::string ssl_handshake_details() const // fixme -- code me
      {
	return "[AppleSSL not implemented]";
      }

      ~SSL()
      {
	ssl_erase();
      }

    private:
      SSL(const AppleSSLContext& ctx)
      {
	ssl_clear();
	try {
	  OSStatus s;

#ifdef OPENVPN_PLATFORM_IPHONE
	  // init SSL object, select client or server mode
	  if (ctx.mode().is_server())
	    ssl = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
	  else if (ctx.mode().is_client())
	    ssl = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
	  else
	    OPENVPN_THROW(ssl_context_error, "AppleSSLContext::SSL: unknown client/server mode");
	  if (ssl == NULL)
	    throw CFException("SSLCreateContext failed");

	  // use TLS v1
	  s = SSLSetProtocolVersionMin(ssl, kTLSProtocol1);
	  if (s)
	    throw CFException("SSLSetProtocolVersionMin failed", s);
#else
	  // init SSL object, select client or server mode
	  if (ctx.mode().is_server())
	    s = SSLNewContext(true, &ssl);
	  else if (ctx.mode().is_client())
	    s = SSLNewContext(false, &ssl);
	  else
	    OPENVPN_THROW(ssl_context_error, "AppleSSLContext::SSL: unknown client/server mode");
	  if (s)
	    throw CFException("SSLNewContext failed", s);

	  // use TLS v1
	  s = SSLSetProtocolVersionEnabled(ssl, kSSLProtocol2, false);
	  if (s)
	    throw CFException("SSLSetProtocolVersionEnabled !S2 failed", s);
	  s = SSLSetProtocolVersionEnabled(ssl, kSSLProtocol3, false);
	  if (s)
	    throw CFException("SSLSetProtocolVersionEnabled !S3 failed", s);
	  s = SSLSetProtocolVersionEnabled(ssl, kTLSProtocol1, true);
	  if (s)
	    throw CFException("SSLSetProtocolVersionEnabled T1 failed", s);
#endif
	  // configure cert, private key, and supporting CAs via identity wrapper
	  s = SSLSetCertificate(ssl, ctx.identity()());
	  if (s)
	    throw CFException("SSLSetCertificate failed", s);

	  // configure ciphertext buffers
	  ct_in.set_frame(ctx.frame());
	  ct_out.set_frame(ctx.frame());

	  // configure the "connection" object to be self
	  s = SSLSetConnection(ssl, this);
	  if (s)
	    throw CFException("SSLSetConnection", s);

	  // configure ciphertext read/write callbacks
	  s = SSLSetIOFuncs(ssl, ct_read_func, ct_write_func);
	  if (s)
	    throw CFException("SSLSetIOFuncs failed", s);
	}
	catch (...)
	  {
	    ssl_erase();
	    throw;
	  }
      }

      static OSStatus ct_read_func(SSLConnectionRef cref, void *data, size_t *length)
      {
	try {
	  SSL *self = (SSL *)cref;
	  const size_t actual = self->ct_in.read((unsigned char *)data, *length);
	  const OSStatus ret = (*length == actual) ? 0 : errSSLWouldBlock;
	  *length = actual;
	  return ret;
	}
	catch (...)
	  {
	    return errSSLInternal;
	  }
      }

      static OSStatus ct_write_func(SSLConnectionRef cref, const void *data, size_t *length)
      {
	try {
	  SSL *self = (SSL *)cref;
	  self->ct_out.write((const unsigned char *)data, *length);
	  return 0;
	}
	catch (...)
	  {
	    return errSSLInternal;
	  }
      }

      void ssl_clear()
      {
	ssl = NULL;
	overflow = false;
      }

      void ssl_erase()
      {
	if (ssl)
	  {
#ifdef OPENVPN_PLATFORM_IPHONE
	    CFRelease(ssl);
#else
	    SSLDisposeContext(ssl);
#endif
	  }
	ssl_clear();
      }

      SSLContextRef ssl; // underlying SSL connection object
      MemQStream ct_in;  // write ciphertext to here
      MemQStream ct_out; // read ciphertext from here
      bool overflow;
    };

    /////// start of main class implementation

    explicit AppleSSLContext(const Config& config)
      : config_(config)
    {
      if (!config_.identity())
	OPENVPN_THROW(ssl_context_error, "AppleSSLContext: identity undefined");	
    }

    SSL::Ptr ssl() const { return SSL::Ptr(new SSL(*this)); }

    const Mode& mode() const { return config_.mode; }

  private:
    const Frame::Ptr& frame() const { return config_.frame; }
    const CF::Array& identity() const { return config_.identity; }

    // load an identity from keychain, return as an array that can
    // be passed to SSLSetCertificate
    static CF::Array load_identity_(const std::string& subj_match)
    {
      const CF::String label = CF::string(subj_match);
      const void *keys[] =   { kSecClass,         kSecMatchSubjectContains, kSecMatchTrustedOnly, kSecReturnRef };
      const void *values[] = { kSecClassIdentity, label(),                  kCFBooleanTrue,       kCFBooleanTrue };
      const CF::Dict query = CF::dict(keys, values, sizeof(keys)/sizeof(keys[0]));
      CF::Generic result;
      const OSStatus s = SecItemCopyMatching(query(), result.mod_ref());
      if (!s && result.defined())
	{
	  const void *asrc[] = { result() };
	  return CF::array(asrc, 1);
	}
      else
	return CF::Array(); // not found
    }

    Config config_;
  };

  typedef AppleSSLContext::Ptr AppleSSLContextPtr;

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_SSL_SSLCTX_H
