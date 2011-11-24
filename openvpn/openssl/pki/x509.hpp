#ifndef OPENVPN_OPENSSL_PKI_X509_H
#define OPENVPN_OPENSSL_PKI_X509_H

#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {

  class X509Base
  {
  public:
    X509Base() : x509_(NULL) {}
    explicit X509Base(::X509 *x509) : x509_(x509) {}

    bool defined() const { return x509_ != NULL; }
    ::X509* obj() const { return x509_; }
    ::X509* obj_dup() const { return dup(x509_); }

    std::string render_pem() const
    {
      if (x509_)
	{
	  BIO *bio = BIO_new(BIO_s_mem());
	  const int ret = PEM_write_bio_X509(bio, x509_);
	  if (ret == 0)
	    {
	      BIO_free(bio);
	      throw OpenSSLException("X509::render_pem");
	    }

	  {
	    char *temp;
	    const int buf_len = BIO_get_mem_data(bio, &temp);
	    std::string ret = std::string(temp, buf_len);
	    BIO_free(bio);
	    return ret;
	  }
	}
      else
	return "";
    }

  private:
    static ::X509 *dup(const ::X509 *x509)
    {
      if (x509)
	return X509_dup(const_cast< ::X509 * >(x509));
      else
	return NULL;
    }

    friend class X509;
    ::X509 *x509_;
  };

  class X509 : public X509Base, public RC<thread_unsafe_refcount>
  {
  public:
    X509() {}

    explicit X509(const std::string& cert_txt)
    {
      parse_pem(cert_txt);
    }

    X509(const X509& other)
    {
      assign(other.x509_);
    }

    void operator=(const X509& other)
    {
      assign(other.x509_);
    }

    void parse_pem(const std::string& cert_txt)
    {
      BIO *bio = BIO_new_mem_buf(const_cast<char *>(cert_txt.c_str()), cert_txt.length());
      if (!bio)
	throw OpenSSLException();

      ::X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
      BIO_free(bio);
      if (!cert)
	throw OpenSSLException("X509::parse_pem");

      erase();
      x509_ = cert;
    }

    void erase()
    {
      if (x509_)
	{
	  X509_free(x509_);
	  x509_ = NULL;
	}
    }

    ~X509()
    {
      erase();
    }

  private:
    void assign(const ::X509 *x509)
    {
      erase();
      x509_ = dup(x509);
    }
  };

  typedef boost::intrusive_ptr<X509> X509Ptr;

  class X509List : public std::vector<X509Ptr>
  {
  public:
    typedef X509 Item;
    typedef X509Ptr ItemPtr;

    bool defined() const { return !empty(); }

    std::string render_pem() const
    {
      std::string ret;
      for (const_iterator i = begin(); i != end(); i++)
	ret += (*i)->render_pem();
      return ret;
    }
  };

} // namespace openvpn

#endif // OPENVPN_OPENSSL_PKI_X509_H
