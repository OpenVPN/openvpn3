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

// Wrap the PolarSSL 1.2 SSL API as defined in <polarssl/ssl.h>
// so that it can be used as the SSL layer by the OpenVPN core.

#ifndef OPENVPN_POLARSSL_SSL_SSLCTX_H
#define OPENVPN_POLARSSL_SSL_SSLCTX_H

#include <vector>
#include <string>
#include <sstream>
#include <cstring>

#include <polarssl/ssl.h>
#include <polarssl/oid.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/mode.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/frame/memq_stream.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/pki/epkibase.hpp>
#include <openvpn/pki/pkcs1.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <openvpn/ssl/nscert.hpp>
#include <openvpn/ssl/tlsver.hpp>
#include <openvpn/ssl/tls_remote.hpp>

#include <openvpn/polarssl/pki/x509cert.hpp>
#include <openvpn/polarssl/pki/x509crl.hpp>
#include <openvpn/polarssl/pki/dh.hpp>
#include <openvpn/polarssl/pki/pkctx.hpp>
#include <openvpn/polarssl/util/error.hpp>

// An SSL Context is essentially a configuration that can be used
// to generate an arbitrary number of actual SSL connections objects.

// PolarSSLContext is an SSL Context implementation that uses the
// PolarSSL library as a backend.

namespace openvpn {

  namespace polarssl_ctx_private {
    static const int aes_cbc_ciphersuites[] = // CONST GLOBAL
      {
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	0
      };
  }

  // Represents an SSL configuration that can be used
  // to instantiate actual SSL sessions.
  template <typename RAND_API>
  class PolarSSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<PolarSSLContext> Ptr;

    OPENVPN_SIMPLE_EXCEPTION(ssl_ciphertext_in_overflow);
    OPENVPN_EXCEPTION(polarssl_external_pki);

    enum {
      MAX_CIPHERTEXT_IN = 64 // maximum number of queued input ciphertext packets
    };

    // The data needed to construct a PolarSSLContext.
    struct Config
    {
      Config() : external_pki(NULL),
		 ssl_debug_level(0),
		 ns_cert_type(NSCert::NONE),
		 tls_version_min(TLSVersion::UNDEF),
		 local_cert_enabled(true),
                 force_aes_cbc_ciphersuites(false) {}

      Mode mode;
      PolarSSLPKI::X509Cert::Ptr crt_chain;  // local cert chain (including client cert + extra certs)
      PolarSSLPKI::X509Cert::Ptr ca_chain;   // CA chain for remote verification
      PolarSSLPKI::X509CRL::Ptr crl_chain;   // CRL chain for remote verification
      PolarSSLPKI::PKContext::Ptr priv_key;  // private key
      std::string priv_key_pwd;              // private key password
      PolarSSLPKI::DH::Ptr dh;               // diffie-hellman parameters (only needed in server mode)
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      int ssl_debug_level;
      NSCert::Type ns_cert_type;
      std::vector<unsigned int> ku; // if defined, peer cert X509 key usage must match one of these values
      std::string eku;              // if defined, peer cert X509 extended key usage must match this OID/string
      std::string tls_remote;
      TLSVersion::Type tls_version_min; // minimum TLS version that we will negotiate
      bool local_cert_enabled;
      bool force_aes_cbc_ciphersuites;
      typename RAND_API::Ptr rng;   // random data source

      // if this callback is defined, no private key needs to be loaded
      void set_external_pki_callback(ExternalPKIBase* external_pki_arg)
      {
	external_pki = external_pki_arg;
      }

      void set_private_key_password(const std::string& pwd)
      {
	priv_key_pwd = pwd;
      }

      void load_ca(const std::string& ca_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(ca_txt, "ca");
	ca_chain = c;
      }

      void load_crl(const std::string& crl_txt)
      {
	PolarSSLPKI::X509CRL::Ptr c = new PolarSSLPKI::X509CRL();
	c->parse(crl_txt);
	crl_chain = c;
      }

      void load_cert(const std::string& cert_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert");
	crt_chain = c;
      }

      void load_cert(const std::string& cert_txt, const std::string& extra_certs_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert");
	if (!extra_certs_txt.empty())
	  c->parse(extra_certs_txt, "extra-certs");
	crt_chain = c;
      }

      void load_private_key(const std::string& key_txt)
      {
	PolarSSLPKI::PKContext::Ptr p = new PolarSSLPKI::PKContext();
	p->parse(key_txt, "config", priv_key_pwd);
	priv_key = p;
      }

      void load_dh(const std::string& dh_txt)
      {
	PolarSSLPKI::DH::Ptr mydh = new PolarSSLPKI::DH();
	mydh->parse(dh_txt, "server-config");
	dh = mydh;
      }

      void load(const OptionList& opt)
      {
	// client/server
	mode = opt.exists("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// ca
	{
	  const std::string ca_txt = opt.cat("ca");
	  load_ca(ca_txt);
	}

	// CRL
	{
	  const std::string crl_txt = opt.cat("crl-verify");
	  if (!crl_txt.empty())
	    load_crl(crl_txt);
	}

	// local cert/key
	if (local_cert_enabled)
	  {
	    // cert/extra-certs
	    {
	      const std::string& cert_txt = opt.get("cert", 1, Option::MULTILINE);
	      const std::string ec_txt = opt.cat("extra-certs");
	      load_cert(cert_txt, ec_txt);
	    }

	    // private key
	    if (!external_pki)
	      {
		const std::string& key_txt = opt.get("key", 1, Option::MULTILINE);
		load_private_key(key_txt);
	      }
	  }

	// DH
	if (mode.is_server())
	  {
	    const std::string& dh_txt = opt.get("dh", 1, Option::MULTILINE);
	    load_dh(dh_txt);
	  }

	// parse ns-cert-type
	ns_cert_type = NSCert::ns_cert_type(opt);

	// parse remote-cert-x options
	KUParse::remote_cert_tls(opt, ku, eku);
	KUParse::remote_cert_ku(opt, ku);
	KUParse::remote_cert_eku(opt, eku);

	// parse tls-remote
	tls_remote = opt.get_optional("tls-remote", 1, 256);

	// parse tls-version-min option
	{
#         if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	    const TLSVersion::Type maxver = TLSVersion::V1_2;
#         elif defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	    const TLSVersion::Type maxver = TLSVersion::V1_1;
#         else
            const TLSVersion::Type maxver = TLSVersion::V1_0;
#         endif
	  tls_version_min = TLSVersion::parse_tls_version_min(opt, maxver);
	}

	// unsupported cert verification options
	{
	}
      }
    };

    // Represents an actual SSL session.
    // Normally instantiated by PolarSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
      // read/write callback errors
      enum {
	// assumes that PolarSSL user-defined errors may start at -0x8000
	CT_WOULD_BLOCK = -0x8000,
	CT_INTERNAL_ERROR = -0x8001
      };

      friend class PolarSSLContext;

    public:
      typedef boost::intrusive_ptr<SSL> Ptr;

      // special return value from read functions -- indicates
      // that no cleartext data is available now (until more
      // ciphertext is pushed into the SSL engine)
      enum {
	SHOULD_RETRY = -1
      };

      void start_handshake()
      {
	ssl_handshake(ssl);
      }

      ssize_t write_cleartext_unbuffered(const void *data, const size_t size)
      {
	const int status = ssl_write(ssl, (const unsigned char*)data, size);
	if (status < 0)
	  {
	    if (status == CT_WOULD_BLOCK)
	      return SHOULD_RETRY;
	    else if (status == CT_INTERNAL_ERROR)
	      throw PolarSSLException("SSL write: internal error");
	    else
	      throw PolarSSLException("SSL write error", status);
	  }
	else
	  return status;
      }

      ssize_t read_cleartext(void *data, const size_t capacity)
      {
	if (!overflow)
	  {
	    const int status = ssl_read(ssl, (unsigned char*)data, capacity);
	    if (status < 0)
	      {
		if (status == CT_WOULD_BLOCK)
		  return SHOULD_RETRY;
		else if (status == CT_INTERNAL_ERROR)
		  throw PolarSSLException("SSL read: internal error");
		else
		  throw PolarSSLException("SSL read error", status);
	      }
	    else
	      return status;
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

      std::string ssl_handshake_details() const
      {
	return ssl_get_version(ssl) + std::string("/") + ssl_get_ciphersuite(ssl);
      }

      ~SSL()
      {
	erase();
      }

    private:
      SSL(PolarSSLContext* ctx)
      {
	clear();
	try {
	  const Config& c = ctx->config;
	  int status;

	  // init SSL object
	  ssl = new ssl_context;
	  status = ssl_init(ssl);
	  if (status < 0)
	    throw PolarSSLException("error in ssl_init", status);

	  // set client/server mode
	  if (c.mode.is_server())
	    ssl_set_endpoint(ssl, SSL_IS_SERVER);
	  else if (c.mode.is_client())
	    ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	  else
	    throw PolarSSLException("unknown client/server mode");

	  // set minimum TLS version
	  if (!c.force_aes_cbc_ciphersuites)
	    {
	      int polar_major;
	      int polar_minor;
	      switch (c.tls_version_min)
		{
		case TLSVersion::V1_0:
		default:
		  polar_major = SSL_MAJOR_VERSION_3;
		  polar_minor = SSL_MINOR_VERSION_1;
		  break;
#               if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	          case TLSVersion::V1_1:
		    polar_major = SSL_MAJOR_VERSION_3;
		    polar_minor = SSL_MINOR_VERSION_2;
		    break;
#               endif
#               if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	          case TLSVersion::V1_2:
		    polar_major = SSL_MAJOR_VERSION_3;
		    polar_minor = SSL_MINOR_VERSION_3;
		    break;
#               endif
	        }
	      ssl_set_min_version(ssl, polar_major, polar_minor);
	    }

	  // peer must present a valid certificate
	  ssl_set_authmode(ssl, SSL_VERIFY_REQUIRED);

	  // set verify callback
	  ssl_set_verify(ssl, verify_callback, ctx);

	  // Allocate session object, but don't support SSL-level session resume.
	  // Note: SSL resume is not enabled because ssl_set_session_cache is not called.
	  // Note: SSL renegotiation is not enabled because ssl_set_renegotiation
	  //       defaults to SSL_RENEGOTIATION_DISABLED and ssl_legacy_renegotiation
	  //       defaults to SSL_LEGACY_NO_RENEGOTIATION.
	  // Also, POLARSSL_SSL_SESSION_TICKETS (compile flag) should be left undefined
	  // in PolarSSL config.h.
	  sess = new ssl_session;
	  std::memset(sess, 0, sizeof(*sess));
	  ssl_set_session(ssl, sess);

	  if (c.force_aes_cbc_ciphersuites)
	    ssl_set_ciphersuites(ssl, polarssl_ctx_private::aes_cbc_ciphersuites);

	  // set CA chain
	  if (c.ca_chain)
	    ssl_set_ca_chain(ssl,
			     c.ca_chain->get(),
			     c.crl_chain ? c.crl_chain->get() : NULL,
			     NULL);
	  else
	    throw PolarSSLException("CA chain not defined");

	  // client cert+key
	  if (c.local_cert_enabled)
	    {
	      if (c.external_pki)
		{
		  // set our own certificate, supporting chain (i.e. extra-certs), and external private key
		  if (c.crt_chain)
		    ssl_set_own_cert_alt(ssl, c.crt_chain->get(), ctx, epki_decrypt, epki_sign, epki_key_len);
		  else
		    throw PolarSSLException("cert is undefined");
		}
	      else
		{
		  // set our own certificate, supporting chain (i.e. extra-certs), and private key
		  if (c.crt_chain && c.priv_key)
		    ssl_set_own_cert(ssl, c.crt_chain->get(), c.priv_key->get());
		  else
		    throw PolarSSLException("cert and/or private key is undefined");
		}
	    }

	  // set DH
	  if (c.dh)
	    {
	      status = ssl_set_dh_param_ctx(ssl, c.dh->get());
	      if (status < 0)
		throw PolarSSLException("error in ssl_set_dh_param_ctx", status);
	    }

	  // configure ciphertext buffers
	  ct_in.set_frame(c.frame);
	  ct_out.set_frame(c.frame);

	  // set BIO
	  ssl_set_bio(ssl, ct_read_func, this, ct_write_func, this);

	  // set RNG
	  if (c.rng)
	    {
	      rng = c.rng;
	      ssl_set_rng(ssl, rng_callback, this);
	    }
	  else
	    throw PolarSSLException("RNG not defined");

	  // set debug callback
	  if (c.ssl_debug_level)
	    ssl_set_dbg(ssl, dbg_callback, ctx);
	}
	catch (...)
	  {
	    erase();
	    throw;
	  }
      }

      // cleartext read callback
      static int ct_read_func(void *arg, unsigned char *data, size_t length)
      {
	try {
	  SSL *self = (SSL *)arg;
	  const size_t actual = self->ct_in.read(data, length);
	  return actual > 0 ? (int)actual : CT_WOULD_BLOCK;
	}
	catch (...)
	  {
	    return CT_INTERNAL_ERROR;
	  }
      }

      // cleartext write callback
      static int ct_write_func(void *arg, const unsigned char *data, size_t length)
      {
	try {
	  SSL *self = (SSL *)arg;
	  self->ct_out.write(data, length);
	  return (int)length;
	}
	catch (...)
	  {
	    return CT_INTERNAL_ERROR;
	  }
      }

      // RNG callback -- return random data to PolarSSL
      static int rng_callback(void *arg, unsigned char *data, size_t len)
      {
	SSL *self = (SSL *)arg;
	return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose PolarSSL error code
      }

      static void dbg_callback(void *arg, int level, const char *text)
      {
	PolarSSLContext *self = (PolarSSLContext *)arg;
	if (level <= self->config.ssl_debug_level)
	  OPENVPN_LOG_NTNL("PolarSSL[" << level << "]: " << text);
      }

      void clear()
      {
	ssl = NULL;
	sess = NULL;
	overflow = false;
      }

      void erase()
      {
	if (ssl)
	  {
	    ssl_free(ssl);
	    delete ssl;
	  }
	if (sess)
	  delete sess;
	clear();
      }

      ssl_context *ssl;	       // underlying SSL connection object
      ssl_session *sess;       // SSL session (tied to ssl object above)
      typename RAND_API::Ptr rng;       // random data source
      bool overflow;
      MemQStream ct_in;    // write ciphertext to here
      MemQStream ct_out;   // read ciphertext from here
    };

    /////// start of main class implementation

    explicit PolarSSLContext(const Config& config_arg)
    {
      config = config_arg;

      if (config.local_cert_enabled)
	{
	  // Verify that cert is defined
	  if (!config.crt_chain)
	    throw PolarSSLException("cert is undefined");
	}
    }

    typename SSL::Ptr ssl() { return typename SSL::Ptr(new SSL(this)); }

    const Mode& mode() const { return config.mode; }
 
    ~PolarSSLContext()
    {
      erase();
    }

  private:
    size_t key_len() const
    {
      return pk_get_size(&config.crt_chain->get()->pk) / 8;
    }

    // ns-cert-type verification

    bool ns_cert_type_defined() const
    {
      return config.ns_cert_type != NSCert::NONE;
    }

    bool verify_ns_cert_type(const x509_crt *cert) const
    {
      if (config.ns_cert_type == NSCert::SERVER)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_SERVER);
      else if (config.ns_cert_type == NSCert::CLIENT)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT);
      else
	return false;
    }

    // remote-cert-ku verification

    bool x509_cert_ku_defined() const
    {
      return config.ku.size() > 0;
    }

    bool verify_x509_cert_ku(const x509_crt *cert)
    {
      if (cert->ext_types & EXT_KEY_USAGE)
	{
	  const unsigned int ku = cert->key_usage;
	  for (std::vector<unsigned int>::const_iterator i = config.ku.begin(); i != config.ku.end(); ++i)
	    {
	      if (ku == *i)
		return true;
	    }
	}
      return false;
    }

    // remote-cert-eku verification

    bool x509_cert_eku_defined() const
    {
      return !config.eku.empty();
    }

    bool verify_x509_cert_eku(x509_crt *cert)
    {
      if (cert->ext_types & EXT_EXTENDED_KEY_USAGE)
	{
	  x509_sequence *oid_seq = &cert->ext_key_usage;
	  while (oid_seq != NULL)
	    {
	      x509_buf *oid = &oid_seq->buf;

	      // first compare against description
	      {
		const char *oid_str = x509_oid_get_description(oid);
		if (oid_str && config.eku == oid_str)
		  return true;
	      }

	      // next compare against OID numeric string
	      {
		char oid_num_str[256];
		const int status = x509_oid_get_numeric_string(oid_num_str, sizeof(oid_num_str), oid);
		if (status >= 0 && config.eku == oid_num_str)
		  return true;
	      }
	      oid_seq = oid_seq->next;
	    }
	}
      return false;
    }

    // Try to return the x509 subject formatted like the OpenSSL X509_NAME_oneline method.
    // Only attributes matched in the switch statements below will be rendered.  All other
    // attributes will be ignored.
    static std::string x509_get_subject(const x509_crt *cert)
    {
      std::string ret;
      for (const x509_name *name = &cert->subject; name != NULL; name = name->next)
	{
	  const char *key = NULL;
	  if (OID_CMP(OID_AT_CN, &name->oid))
	    key = "CN";
	  else if (OID_CMP(OID_AT_COUNTRY, &name->oid))
	    key = "C";
	  else if (OID_CMP(OID_AT_LOCALITY, &name->oid))
	    key = "L";
	  else if (OID_CMP(OID_AT_STATE, &name->oid))
	    key = "ST";
	  else if (OID_CMP(OID_AT_ORGANIZATION, &name->oid))
	    key = "O";
	  else if (OID_CMP(OID_AT_ORG_UNIT, &name->oid))
	    key = "OU";
	  else if (OID_CMP(OID_PKCS9_EMAIL, &name->oid))
	    key = "emailAddress";

	  // make sure that key is defined and value has no embedded nulls
	  if (key && !string::embedded_null((const char *)name->val.p, name->val.len))
	    ret += "/" + std::string(key) + "=" + std::string((const char *)name->val.p, name->val.len);
	}
      return ret;
    }

    static std::string x509_get_common_name(const x509_crt *cert)
    {
      const x509_name *name = &cert->subject;

      // find common name
      while (name != NULL)
	{
	  if (OID_CMP(OID_AT_CN, &name->oid))
	    break;
	  name = name->next;
	}

      if (name)
	return std::string((const char *)name->val.p, name->val.len);
      else
	return std::string("");
    }

    static std::string fmt_polarssl_verify_flags(const int flags)
    {
      std::ostringstream os;
      if (flags & BADCERT_EXPIRED)
	os << "CERT_EXPIRED ";
      if (flags & BADCERT_REVOKED)
	os << "CERT_REVOKED ";
      if (flags & BADCERT_CN_MISMATCH)
	os << "CN_MISMATCH ";
      if (flags & BADCERT_NOT_TRUSTED)
	os << "CERT_NOT_TRUSTED ";
      if (flags & BADCRL_NOT_TRUSTED)
	os << "CRL_NOT_TRUSTED ";
      if (flags & BADCRL_EXPIRED)
	os << "CRL_EXPIRED ";
      if (flags & BADCERT_MISSING)
	os << "CERT_MISSING ";
      if (flags & BADCERT_SKIP_VERIFY)
	os << "CERT_SKIP_VERIFY ";
      if (flags & BADCERT_OTHER)
	os << "CERT_OTHER ";
      return os.str();
    }

    static std::string status_string(const x509_crt *cert, const int depth, const int *flags)
    {
      std::ostringstream os;
      std::string status_str = "OK";
      if (*flags)
	status_str = "FAIL " + fmt_polarssl_verify_flags(*flags);
      os << "VERIFY "
	 << status_str
	 << ": depth=" << depth
	 << std::endl << cert_info(cert);
      return os.str();
    }

    static int verify_callback(void *arg, x509_crt *cert, int depth, int *flags)
    {
      PolarSSLContext *self = (PolarSSLContext *)arg;
      bool fail = false;

      // log status
      OPENVPN_LOG_SSL(status_string(cert, depth, flags));

      // leaf-cert verification
      if (depth == 0)
	{
	  // verify ns-cert-type
	  if (self->ns_cert_type_defined() && !self->verify_ns_cert_type(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	      fail = true;
	    }

	  // verify X509 key usage
	  if (self->x509_cert_ku_defined() && !self->verify_x509_cert_ku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 key usage in leaf certificate");
	      fail = true;
	    }

	  // verify X509 extended key usage
	  if (self->x509_cert_eku_defined() && !self->verify_x509_cert_eku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 extended key usage in leaf certificate");
	      fail = true;
	    }

	  // verify tls-remote
	  if (!self->config.tls_remote.empty())
	    {
	      const std::string subject = TLSRemote::sanitize_x509_name(x509_get_subject(cert));
	      const std::string common_name = TLSRemote::sanitize_common_name(x509_get_common_name(cert));
	      TLSRemote::log(self->config.tls_remote, subject, common_name);
	      if (!TLSRemote::test(self->config.tls_remote, subject, common_name))
		{
		  OPENVPN_LOG_SSL("VERIFY FAIL -- tls-remote match failed");
		  fail = true;
		}
	    }
	}

      if (fail)
	*flags |= BADCERT_OTHER;
      return 0;
    }

    static std::string cert_info(const x509_crt *cert, const char *prefix = NULL)
    {
      char buf[512];
      const int size = x509_crt_info(buf, sizeof(buf), prefix ? prefix : "", cert);
      if (size >= 0)
	return buf;
      else
	return "error rendering cert";
    }

    void erase()
    {
    }

    static int epki_decrypt(void *arg,
			    int mode,
			    size_t *olen,
			    const unsigned char *input,
			    unsigned char *output,
			    size_t output_max_len)
    {
      OPENVPN_LOG_SSL("PolarSSLContext::epki_decrypt is unimplemented, mode=" << mode
		      << " output_max_len=" << output_max_len);
      return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
    }

    static int epki_sign(void *arg,
			 int (*f_rng)(void *, unsigned char *, size_t),
			 void *p_rng,
			 int mode,
			 md_type_t md_alg,
			 unsigned int hashlen,
			 const unsigned char *hash,
			 unsigned char *sig)
    {
      PolarSSLContext *self = (PolarSSLContext *) arg;
      try {
	if (mode == RSA_PRIVATE)
	  {
	    size_t digest_prefix_len = 0;
	    const unsigned char *digest_prefix = NULL;

	    /* get signature type */
	    switch (md_alg) {
	    case POLARSSL_MD_NONE:
	      break;
	    case POLARSSL_MD_MD2:
	      digest_prefix = PKCS1::DigestPrefix::MD2;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::MD2);
	      break;
	    case POLARSSL_MD_MD5:
	      digest_prefix = PKCS1::DigestPrefix::MD5;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::MD5);
	      break;
	    case POLARSSL_MD_SHA1:
	      digest_prefix = PKCS1::DigestPrefix::SHA1;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA1);
	      break;
	    case POLARSSL_MD_SHA256:
	      digest_prefix = PKCS1::DigestPrefix::SHA256;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA256);
	      break;
	    case POLARSSL_MD_SHA384:
	      digest_prefix = PKCS1::DigestPrefix::SHA384;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA384);
	      break;
	    case POLARSSL_MD_SHA512:
	      digest_prefix = PKCS1::DigestPrefix::SHA512;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA512);
	      break;
	    default:
	      OPENVPN_LOG_SSL("PolarSSLContext::epki_sign unrecognized hash_id, mode=" << mode
			      << " md_alg=" << md_alg << " hashlen=" << hashlen);
	      return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	    }

	    /* concatenate digest prefix with hash */
	    BufferAllocated from_buf(digest_prefix_len + hashlen, 0);
	    if (digest_prefix_len)
	      from_buf.write(digest_prefix, digest_prefix_len);
	    from_buf.write(hash, hashlen);

	    /* convert from_buf to base64 */
	    const std::string from_b64 = base64->encode(from_buf);

	    /* get signature */
	    std::string sig_b64;
	    const bool status = self->config.external_pki->sign("RSA_RAW", from_b64, sig_b64);
	    if (!status)
	      throw polarssl_external_pki("could not obtain signature");

	    /* decode base64 signature to binary */
	    const size_t len = self->key_len();
	    Buffer sigbuf(sig, len, false);
	    base64->decode(sigbuf, sig_b64);

	    /* verify length */
	    if (sigbuf.size() != len)
	      throw polarssl_external_pki("incorrect signature length");

	    /* success */
	    return 0;
	  }
	else
	  {
	    OPENVPN_LOG_SSL("PolarSSLContext::epki_sign unrecognized parameters, mode=" << mode 
			    << " md_alg=" << md_alg << " hashlen=" << hashlen);
	    return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	  }
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("PolarSSLContext::epki_sign: " << e.what());
	  return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	}
    }

    static size_t epki_key_len(void *arg)
    {
      PolarSSLContext *self = (PolarSSLContext *) arg;
      return self->key_len();
    }

    Config config;
  };

} // namespace openvpn

#endif
