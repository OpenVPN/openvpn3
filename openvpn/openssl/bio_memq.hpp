/*
 * This code implements an OpenSSL BIO object based on the MemQ buffer
 * queue object.  This is done to provide a memory BIO with datagram
 * semantics to use with DTLS sessions.
 */

#ifndef OPENVPN_BUFFER_BIO_MEMQ_H
#define OPENVPN_BUFFER_BIO_MEMQ_H

#include <iostream>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openvpn/buffer/memq.hpp>

namespace openvpn {

#define BIO_TYPE_MEMQ (94|BIO_TYPE_SOURCE_SINK) /* make sure type 94 doesn't collide with anything in bio.h */

class BioMemQ : public MemQ {
public:
  BioMemQ()
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
	std::cout << "*** BSS_MEMQ unimplemented ctrl method=" << cmd << std::endl; // fixme
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

BIO_METHOD *BIO_s_memq(void);

static inline BioMemQ *
memq_from_bio(BIO *b)
{
  if (b->method->type == BIO_TYPE_MEMQ)
    return (BioMemQ *)b->ptr;
  else
    return NULL;
}

static inline const BioMemQ *
c_memq_from_bio(const BIO *b)
{
  if (b->method->type == BIO_TYPE_MEMQ)
    return (const BioMemQ *)b->ptr;
  else
    return NULL;
}

} // namespace openvpn

#endif // OPENVPN_BUFFER_BIO_MEMQ_H
