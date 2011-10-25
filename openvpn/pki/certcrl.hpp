#ifndef OPENVPN_PKI_CERTCRL_H
#define OPENVPN_PKI_CERTCRL_H

#include <string>
#include <sstream>
#include <fstream>

#include <boost/algorithm/string.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/pki/x509.hpp>
#include <openvpn/pki/crl.hpp>

namespace openvpn {

  namespace parse_ca {

    OPENVPN_EXCEPTION(parse_cert_crl_error);

    inline void from_istream(std::istream& in, const std::string title, X509List* cert_list, CRLList* crl_list)
    {
      static const char cert_start[] = "-----BEGIN CERTIFICATE-----";
      static const char cert_end[] = "-----END CERTIFICATE-----";
      static const char crl_start[] = "-----BEGIN X509 CRL-----";
      static const char crl_end[] = "-----END X509 CRL-----";

      enum {
	S_OUTSIDE, // outside of CERT or CRL block
	S_IN_CERT, // in CERT block
	S_IN_CRL,  // in CRL block
      };

      std::string line;
      int state = S_OUTSIDE;
      std::string item = "";
      int line_num = 0;

      while (std::getline(in, line))
	{
	  line_num++;
	  boost::trim(line);
	  if (state == S_OUTSIDE)
	    {
	      if (line == cert_start)
		{
		  if (!cert_list)
		    OPENVPN_THROW(parse_cert_crl_error, title << ":" << line_num << " : not expecting a CERT");
		  state = S_IN_CERT;
		}
	      else if (line == crl_start)
		{
		  if (!crl_list)
		    OPENVPN_THROW(parse_cert_crl_error, title << ":" << line_num << " : not expecting a CRL");
		  state = S_IN_CRL;
		}
	    }
	  if (state != S_OUTSIDE)
	    {
	      item += line;
	      item += "\n";
	    }
	  if (state == S_IN_CERT && line == cert_end)
	    {
	      X509Ptr x509(new X509());
	      try {
		x509->parse_pem(item);
	      }
	      catch (std::exception& e)
		{
		  OPENVPN_THROW(parse_cert_crl_error, title << ":" << line_num << " : error parsing CERT: " << e.what());
		}
	      cert_list->push_back(x509);
	      state = S_OUTSIDE;
	      item = "";
	    }
	  if (state == S_IN_CRL && line == crl_end)
	    {
	      CRLPtr crl(new CRL());
	      try {
		crl->parse_pem(item);
	      }
	      catch (std::exception& e)
		{
		  OPENVPN_THROW(parse_cert_crl_error, title << ":" << line_num << " : error parsing CRL: " << e.what());
		}
	      crl_list->push_back(crl);
	      state = S_OUTSIDE;
	      item = "";
	    }
	}
      if (state != S_OUTSIDE)
	OPENVPN_THROW(parse_cert_crl_error, title << " : CERT/CRL content ended unexpectedly without END marker");
    }

    inline void from_string(const std::string content, const std::string title, X509List* cert_list, CRLList* crl_list = NULL)
    {
      std::stringstream in(content);
      from_istream(in, title, cert_list, crl_list);
    }

    inline void from_file(const std::string filename, X509List* cert_list, CRLList* crl_list = NULL)
    {
      std::ifstream ifs(filename.c_str());
      if (!ifs)
	OPENVPN_THROW(open_file_error, "cannot open CERT/CRL file " << filename);
      from_istream(ifs, filename, cert_list, crl_list);
      if (ifs.bad())
	OPENVPN_THROW(open_file_error, "cannot read CERT/CRL file " << filename);
    }

  } // namespace parse_ca

  class CertCRLList
  {
  public:
    void parse_pem(const std::string content, const std::string title)
    {
      parse_ca::from_string(content, title, &certs, &crls);
    }

    void parse_pem_file(const std::string filename)
    {
      parse_ca::from_file(filename, &certs, &crls);
    }

    std::string render_pem() const
    {
      return certs.render_pem() + crls.render_pem();
    }

    X509List certs;
    CRLList crls;
  };

} // namespace openvpn

#endif // OPENVPN_PKI_CERTCRL_H
