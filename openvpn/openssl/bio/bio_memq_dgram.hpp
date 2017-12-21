//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

// This code implements an OpenSSL BIO object for datagrams based on the
// MemQ buffer queue object.

#ifndef OPENVPN_OPENSSL_BIO_BIO_MEMQ_DGRAM_H
#define OPENVPN_OPENSSL_BIO_BIO_MEMQ_DGRAM_H

#include <cstring> // for std::strlen

#include <openssl/err.h>
#include <openssl/bio.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/frame/memq_dgram.hpp>

namespace openvpn {
  namespace bmq_dgram {

    class MemQ : public MemQDgram {
    public:
      MemQ()
      {
	mtu = 0;
	query_mtu_return = 0;
	std::memset(&next_timeout, 0, sizeof(next_timeout));
      }

      void set_mtu(long mtu) { query_mtu_return = mtu; }
      const struct timeval *get_next_timeout(void) const { return &next_timeout; }

      long ctrl (BIO *b, int cmd, long num, void *ptr)
      {
	long ret = 1;

	switch (cmd)
	  {
	  case BIO_CTRL_RESET:
	    clear();
	    break;
	  case BIO_CTRL_EOF:
	    ret = (long)empty();
	    break;
	  case BIO_C_SET_BUF_MEM_EOF_RETURN:
	    b->num = (int)num;
	    break;
	  case BIO_CTRL_GET_CLOSE:
	    ret = (long)b->shutdown;
	    break;
	  case BIO_CTRL_SET_CLOSE:
	    b->shutdown = (int)num;
	    break;
	  case BIO_CTRL_WPENDING:
	    ret = 0L;
	    break;
	  case BIO_CTRL_PENDING:
	    ret = (long)pending();
	    break;
	  case BIO_CTRL_DUP:
	  case BIO_CTRL_FLUSH:
	    ret = 1;
	    break;
	  case BIO_CTRL_DGRAM_QUERY_MTU:
	    ret = mtu = query_mtu_return;
	    break;
	  case BIO_CTRL_DGRAM_GET_MTU:
	    ret = mtu;
	    break;
	  case BIO_CTRL_DGRAM_SET_MTU:
	    ret = mtu = num;
	    break;
	  case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
	    std::memcpy(&next_timeout, ptr, sizeof(struct timeval));		
	    break;
	  default:
	    //OPENVPN_LOG("*** MemQ-dgram unimplemented ctrl method=" << cmd);
	    ret = 0;
	    break;
	  }
	return (ret);
      }

    private:
      long mtu;
      long query_mtu_return;
      struct timeval next_timeout;
    };

    namespace bio_memq_internal {
      enum {
	BIO_TYPE_MEMQ = (94|BIO_TYPE_SOURCE_SINK) // make sure type 94 doesn't collide with anything in bio.h
      };

      inline int memq_new (BIO *b)
      {
	MemQ *bmq = new MemQ();
	if (!bmq)
	  return 0;
	b->shutdown = 1;
	b->init = 1;
	b->num = -1;
	b->ptr = (void *)bmq;
	return 1;
      }

      inline int memq_free (BIO *b)
      {
	if (b == nullptr)
	  return (0);
	if (b->shutdown)
	  {
	    if ((b->init) && (b->ptr != nullptr))
	      {
		MemQ *bmq = (MemQ*)b->ptr;
		delete bmq;
		b->ptr = nullptr;
	      }
	  }
	return 1;
      }

      inline int memq_write (BIO *b, const char *in, int len)
      {
	MemQ *bmq = (MemQ*)b->ptr;
	if (in)
	  {
	    BIO_clear_retry_flags (b);
	    try {
	      if (len)
		bmq->write((const unsigned char *)in, (size_t)len);
	      return len;
	    }
	    catch (...)
	      {
		BIOerr(BIO_F_MEM_WRITE, BIO_R_INVALID_ARGUMENT);
		return -1;
	      }
	  }
	else
	  {
	    BIOerr(BIO_F_MEM_WRITE, BIO_R_NULL_PARAMETER);
	    return -1;
	  }
      }

      inline int memq_read (BIO *b, char *out, int size)
      {
	MemQ *bmq = (MemQ*)b->ptr;
	int ret = -1;
	BIO_clear_retry_flags (b);
	if (!bmq->empty())
	  {
	    try {
	      ret = (int)bmq->read((unsigned char *)out, (size_t)size);
	    }
	    catch (...)
	      {
		BIOerr(BIO_F_MEM_READ, BIO_R_INVALID_ARGUMENT);
		return -1;
	      }
	  }
	else
	  {
	    ret = b->num;
	    if (ret != 0)
	      BIO_set_retry_read (b);
	  }
	return ret;
      }

      inline long memq_ctrl (BIO *b, int cmd, long arg1, void *arg2)
      {
	MemQ *bmq = (MemQ*)b->ptr;
	return bmq->ctrl(b, cmd, arg1, arg2);
      }

      inline int memq_puts (BIO *b, const char *str)
      {
	const int len = std::strlen (str);
	const int ret = memq_write (b, str, len);
	return ret;
      }

      BIO_METHOD memq_method =
	{
	  BIO_TYPE_MEMQ,
	  "datagram memory queue",
	  memq_write,
	  memq_read,
	  memq_puts,
	  nullptr, /* memq_gets */
	  memq_ctrl,
	  memq_new,
	  memq_free,
	  nullptr,
	};

    } // namespace bio_memq_internal

    inline BIO_METHOD *BIO_s_memq(void)
    {
      return (&bio_memq_internal::memq_method);
    }

    inline MemQ *memq_from_bio(BIO *b)
    {
      if (b->method->type == bio_memq_internal::BIO_TYPE_MEMQ)
	return (MemQ *)b->ptr;
      else
	return nullptr;
    }

    inline const MemQ *const_memq_from_bio(const BIO *b)
    {
      if (b->method->type == bio_memq_internal::BIO_TYPE_MEMQ)
	return (const MemQ *)b->ptr;
      else
	return nullptr;
    }

  } // namespace bmq_dgram
} // namespace openvpn

#endif // OPENVPN_OPENSSL_BIO_BIO_MEMQ_DGRAM_H
