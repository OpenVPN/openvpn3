#ifndef OPENVPN_PKI_DH_H
#define OPENVPN_PKI_DH_H

#include <string>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {

  class DH
  {
  public:
    DH() : dh_(NULL) {}
    DH(const DH& other)
      : dh_(NULL)
    {
      assign(other.dh_);
    }
    void operator=(const DH& other)
    {
      assign(other.dh_);
    }

    bool defined() const { return dh_ != NULL; }
    ::DH* obj() const { return dh_; }

    void parse_pem(const std::string dh_txt)
    {
      BIO *bio = BIO_new_mem_buf(const_cast<char *>(dh_txt.c_str()), dh_txt.length());
      if (!bio)
	throw OpenSSLException();

      ::DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
      if (!dh)
	throw OpenSSLException("DH::parse_pem");

      erase();
      dh_ = dh;
    }

    std::string render_pem() const
    {
      if (dh_)
	{
	  BIO *bio = BIO_new(BIO_s_mem());
	  const int ret = PEM_write_bio_DHparams(bio, dh_);
	  if (ret == 0)
	    {
	      BIO_free(bio);
	      throw OpenSSLException("DH::render_pem");
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
      if (dh_)
	{
	  DH_free(dh_);
	  dh_ = NULL;
	}
    }

    ~DH()
    {
      erase();
    }

  private:
    static ::DH *dup(const ::DH *dh)
    {
      if (dh)
	return DHparams_dup(const_cast< ::DH * >(dh));
      else
	return NULL;
    }

    void assign(const ::DH *dh)
    {
      erase();
      dh_ = dup(dh);
    }

    ::DH *dh_;
  };

} // namespace openvpn

#endif // OPENVPN_PKI_DH_H

