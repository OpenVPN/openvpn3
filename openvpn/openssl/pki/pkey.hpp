#ifndef OPENVPN_OPENSSL_PKI_PKEY_H
#define OPENVPN_OPENSSL_PKI_PKEY_H

#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {

  class PKey
  {
  public:
    PKey() : pkey_(NULL) {}

    explicit PKey(const std::string& pkey_txt)
      : pkey_(NULL)
    {
      parse_pem(pkey_txt);
    }

    PKey(const PKey& other)
      : pkey_(NULL)
    {
      assign(other.pkey_);
    }

    void operator=(const PKey& other)
    {
      assign(other.pkey_);
    }

    bool defined() const { return pkey_ != NULL; }
    EVP_PKEY* obj() const { return pkey_; }

    void parse_pem(const std::string& pkey_txt)
    {
      BIO *bio = BIO_new_mem_buf(const_cast<char *>(pkey_txt.c_str()), pkey_txt.length());
      if (!bio)
	throw OpenSSLException();

      EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      BIO_free(bio);
      if (!pkey)
	throw OpenSSLException("PKey::parse_pem");

      erase();
      pkey_ = pkey;
    }

    std::string render_pem() const
    {
      if (pkey_)
	{
	  BIO *bio = BIO_new(BIO_s_mem());
	  const int ret = PEM_write_bio_PrivateKey(bio, pkey_, NULL, NULL, 0, NULL, NULL);
	  if (ret == 0)
	    {
	      BIO_free(bio);
	      throw OpenSSLException("PKey::render_pem");
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
      if (pkey_)
	{
	  EVP_PKEY_free(pkey_);
	  pkey_ = NULL;
	}
    }

    ~PKey()
    {
      erase();
    }

  private:
    static EVP_PKEY *dup(const EVP_PKEY *pkey)
    {
      // No OpenSSL EVP_PKEY_dup method so we roll our own 
      if (pkey)
	{
	  EVP_PKEY* pDupKey = EVP_PKEY_new();
	  RSA* pRSA = EVP_PKEY_get1_RSA(const_cast<EVP_PKEY *>(pkey));
	  RSA* pRSADupKey = RSAPrivateKey_dup(pRSA);
	  RSA_free(pRSA);
	  EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
	  RSA_free(pRSADupKey);
	  return pDupKey;
	}
      else
	return NULL;
    }

    void assign(const EVP_PKEY *pkey)
    {
      erase();
      pkey_ = dup(pkey);
    }

    EVP_PKEY *pkey_;
  };

} // namespace openvpn

#endif // OPENVPN_OPENSSL_PKI_PKEY_H
