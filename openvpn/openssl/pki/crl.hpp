#ifndef OPENVPN_OPENSSL_PKI_CRL_H
#define OPENVPN_OPENSSL_PKI_CRL_H

#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {

  class CRL : public RC<thread_unsafe_refcount>
  {
  public:
    CRL() : crl_(NULL) {}

    explicit CRL(const std::string& crl_txt)
      : crl_(NULL)
    {
      parse_pem(crl_txt);
    }

    CRL(const CRL& other)
      : crl_(NULL)
    {
      assign(other.crl_);
    }

    void operator=(const CRL& other)
    {
      assign(other.crl_);
    }

    bool defined() const { return crl_ != NULL; }
    X509_CRL* obj() const { return crl_; }

    void parse_pem(const std::string& crl_txt)
    {
      BIO *bio = BIO_new_mem_buf(const_cast<char *>(crl_txt.c_str()), crl_txt.length());
      if (!bio)
	throw OpenSSLException();

      X509_CRL *crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
      BIO_free(bio);
      if (!crl)
	throw OpenSSLException("CRL::parse_pem");

      erase();
      crl_ = crl;
    }

    std::string render_pem() const
    {
      if (crl_)
	{
	  BIO *bio = BIO_new(BIO_s_mem());
	  const int ret = PEM_write_bio_X509_CRL(bio, crl_);
	  if (ret == 0)
	    {
	      BIO_free(bio);
	      throw OpenSSLException("CRL::render_pem");
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

    void erase()
    {
      if (crl_)
	{
	  X509_CRL_free(crl_);
	  crl_ = NULL;
	}
    }

    ~CRL()
    {
      erase();
    }

  private:
    static X509_CRL *dup(const X509_CRL *crl)
    {
      if (crl)
	{
	  return X509_CRL_dup(const_cast<X509_CRL *>(crl));
	}
      else
	return NULL;
    }

    void assign(const X509_CRL *crl)
    {
      erase();
      crl_ = dup(crl);
    }

    X509_CRL *crl_;
  };

  typedef boost::intrusive_ptr<CRL> CRLPtr;

  class CRLList : public std::vector<CRLPtr>
  {
  public:
    typedef CRL Item;
    typedef CRLPtr ItemPtr;

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

#endif // OPENVPN_OPENSSL_PKI_CRL_H
