//
//  httpdigest.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_PROXY_HTTPDIGEST_H
#define OPENVPN_PROXY_HTTPDIGEST_H

#include <cstring>
#include <string>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/hexstr.hpp>

namespace openvpn {
  namespace HTTPProxy {

    template <typename CRYPTO_API>
    class Digest
    {
      class HashString
      {
      public:
	HashString(const typename CRYPTO_API::Digest& md)
	  : ctx(md) {}

	void update(const std::string& str)
	{
	  ctx.update((unsigned char *)str.c_str(), str.length());
	}

	void update(const const char *str)
	{
	  ctx.update((unsigned char *)str, strlen(str));
	}

	void update(const const char c)
	{
	  ctx.update((unsigned char *)&c, 1);
	}

	void update(const Buffer& buf)
	{
	  ctx.update(buf.c_data(), buf.size());
	}

	BufferPtr final()
	{
	  BufferPtr ret(new BufferAllocated(ctx.size(), BufferAllocated::ARRAY));
	  ctx.final(ret->data());
	  return ret;
	}

	std::string final_hex()
	{
	  BufferPtr bp = final();
	  return render_hex(*bp);
	}

      private:
	typename CRYPTO_API::DigestContext ctx;
      };

    public:
      // calculate H(A1) as per spec
      static std::string calcHA1(const std::string& alg,
				 const std::string& username,
				 const std::string& realm,
				 const std::string& password,
				 const std::string& nonce,
				 const std::string& cnonce)
      {
	HashString h1(CRYPTO_API::Digest::md5());
	h1.update(username);
	h1.update(':');
	h1.update(realm);
	h1.update(':');
	h1.update(password);
	BufferPtr result = h1.final();

	if (string::strcasecmp(alg, "md5-sess") == 0)
	  {
	    HashString h2(CRYPTO_API::Digest::md5());
	    h2.update(*result);
	    h2.update(':');
	    h2.update(nonce);
	    h2.update(':');
	    h2.update(cnonce);
	    result = h2.final();
	  }
	return render_hex(*result);
      }

      // calculate request-digest/response-digest as per HTTP Digest spec
      static std::string calcResponse(const std::string& hA1,         // H(A1)
				      const std::string& nonce,       // nonce from server
				      const std::string& nonce_count, // 8 hex digits
				      const std::string& cnonce,      // client nonce
				      const std::string& qop,         // qop-value: "", "auth", "auth-int"
				      const std::string& method,      // method from the request
				      const std::string& digestUri,   // requested URI
				      const std::string& hEntity)     // H(entity body) if qop="auth-int"
      {
	// calculate H(A2)
	HashString h1(CRYPTO_API::Digest::md5());
	h1.update(method);
	h1.update(':');
	h1.update(digestUri);
	if (string::strcasecmp(qop, "auth-int") == 0)
	  {
	    h1.update(':');
	    h1.update(hEntity);
	  }
	const std::string hA2 = h1.final_hex();

	// calculate response
	HashString h2(CRYPTO_API::Digest::md5());
	h2.update(hA1);
	h2.update(':');
	h2.update(nonce);
	h2.update(':');
	if (!qop.empty())
	  {
	    h2.update(nonce_count);
	    h2.update(':');
	    h2.update(cnonce);
	    h2.update(':');
	    h2.update(qop);
	    h2.update(':');
	  }
	h2.update(hA2);
	return h2.final_hex();
      }
    };
  }
}

#endif
