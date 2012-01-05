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
#include <openvpn/log/log.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/frame/memq_stream.hpp>
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
      enum {
	DEBUG = 1<<0,
      };
      typedef unsigned int Flags;

      Config() : flags(0) {}

      Mode mode;
      Flags flags;
      CF::Array identity; // as returned by load_identity
      Frame::Ptr frame;

      void enable_debug()
      {
	flags |= DEBUG;
      }

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
    };

    // Represents an actual SSL session.
    // Normally instantiated by AppleSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
    public:
      enum {
	SHOULD_RETRY = -1
      };

      SSL(const AppleSSLContext& ctx)
      {
	ssl_clear();
	try {
	  OSStatus s;

	  // init SSL object, select client or server mode
	  if (ctx.mode().is_server())
	    s = SSLNewContext(true, &ssl);
	  else if (ctx.mode().is_client())
	    s = SSLNewContext(false, &ssl);
	  else
	    OPENVPN_THROW(ssl_context_error, "AppleSSLContext::SSL: unknown client/server mode");
	  if (s)
	    throw CFException(s, "SSLNewContext failed");

	  // use TLS v1
	  s = SSLSetProtocolVersionEnabled(ssl, kSSLProtocol2, false);
	  if (s)
	    throw CFException(s, "SSLSetProtocolVersionEnabled !S2 failed");
	  s = SSLSetProtocolVersionEnabled(ssl, kSSLProtocol3, false);
	  if (s)
	    throw CFException(s, "SSLSetProtocolVersionEnabled !S3 failed");
	  s = SSLSetProtocolVersionEnabled(ssl, kTLSProtocol1, true);
	  if (s)
	    throw CFException(s, "SSLSetProtocolVersionEnabled T1 failed");

	  // configure cert, private key, and supporting CAs via identity wrapper
	  s = SSLSetCertificate(ssl, ctx.identity()());
	  if (s)
	    throw CFException(s, "SSLSetCertificate failed");

	  // configure ciphertext buffers
	  ct_in.set_frame(ctx.frame());
	  ct_out.set_frame(ctx.frame());

	  // configure the "connection" object to be self
	  s = SSLSetConnection(ssl, this);
	  if (s)
	    throw CFException(s, "SSLSetConnection");

	  // configure ciphertext read/write callbacks
	  s = SSLSetIOFuncs(ssl, ct_read_func, ct_write_func);
	  if (s)
	    throw CFException(s, "SSLSetIOFuncs failed");
	}
	catch (...)
	  {
	    ssl_erase();
	    throw;
	  }
      }

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
	      throw CFException(status, "AppleSSLContext::SSL::write_cleartext failed");
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
		  throw CFException(status, "AppleSSLContext::SSL::read_cleartext failed");
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

      ~SSL()
      {
	ssl_erase();
      }

    private:
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
	  SSLDisposeContext(ssl);
	ssl_clear();
      }

      SSLContextRef ssl; // underlying SSL connection object
      MemQStream ct_in;  // write ciphertext to here
      MemQStream ct_out; // read ciphertext from here
      bool overflow;
    };

    typedef boost::intrusive_ptr<SSL> SSLPtr;

    explicit AppleSSLContext(const Config& config)
      : config_(config)
    {
      if (!config_.identity())
	OPENVPN_THROW(ssl_context_error, "AppleSSLContext: identity undefined");	
    }

    SSLPtr ssl() const { return SSLPtr(new SSL(*this)); }

    const Mode& mode() const { return config_.mode; }
    Config::Flags flags() const { return config_.flags; }
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

  private:
    Config config_;
  };

  typedef AppleSSLContext::Ptr AppleSSLContextPtr;

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_SSL_SSLCTX_H
