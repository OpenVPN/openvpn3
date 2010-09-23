#include <string.h>
#include <openvpn/openssl/bio_memq.hpp>

namespace openvpn {

static int
memq_new (BIO *b)
{
  BioMemQ *bmq = new BioMemQ();
  if (!bmq)
    return 0;
  b->shutdown = 1;
  b->init = 1;
  b->num = -1;
  b->ptr = (void *)bmq;
  return 1;
}

static int
memq_free (BIO *b)
{
  if (b == NULL)
    return (0);
  if (b->shutdown)
    {
      if ((b->init) && (b->ptr != NULL))
	{
	  BioMemQ *bmq = (BioMemQ*)b->ptr;
	  delete bmq;
	  b->ptr = NULL;
	}
    }
  return 1;
}

static int
memq_write (BIO *b, const char *in, int len)
{
  BioMemQ *bmq = (BioMemQ*)b->ptr;
  if (in)
    {
      BIO_clear_retry_flags (b);
      if (len)
	bmq->write((const void *)in, (size_t)len);
      return len;
    }
  else
    {
      BIOerr(BIO_F_MEM_WRITE, BIO_R_NULL_PARAMETER);
      return -1;
    }
}

static int
memq_read (BIO *b, char *out, int size)
{
  BioMemQ *bmq = (BioMemQ*)b->ptr;
  int ret = -1;
  BIO_clear_retry_flags (b);
  if (!bmq->empty())
    {
      ret = (int)bmq->read((void *)out, (size_t)size);
    }
  else
    {
      ret = b->num;
      if (ret != 0)
	BIO_set_retry_read (b);
    }
  return ret;
}

static long
memq_ctrl (BIO *b, int cmd, long arg1, void *arg2)
{
  BioMemQ *bmq = (BioMemQ*)b->ptr;
  return bmq->ctrl(b, cmd, arg1, arg2);
}

static int
memq_puts (BIO *b, const char *str)
{
  const int len = strlen (str);
  const int ret = memq_write (b, str, len);
  return ret;
}

static BIO_METHOD memq_method =
  {
    BIO_TYPE_MEMQ,
    "datagram memory queue",
    memq_write,
    memq_read,
    memq_puts,
    NULL, /* memq_gets */
    memq_ctrl,
    memq_new,
    memq_free,
    NULL,
  };

BIO_METHOD *
BIO_s_memq(void)
{
  return (&memq_method);
}

} // namespace openvpn
