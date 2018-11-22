//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2019 OpenVPN Inc.
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


#pragma once

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/bio.h>
#include <openssl/crypto.h>

// make sure type 94 doesn't collide with anything in bio.h
// Start with the same number as before

static int lastindex = 94;
inline int BIO_get_new_index(void)
{
  int newval = lastindex | BIO_TYPE_SOURCE_SINK;
  lastindex++;
  return newval;
}

inline BIO_METHOD *BIO_meth_new(int type, const char *name)
{
  BIO_METHOD *biom = new BIO_METHOD;

  if ((biom->name = OPENSSL_strdup(name)) == nullptr)
    {
      delete biom;
      BIOerr(BIO_F_BIO_NEW, ERR_R_MALLOC_FAILURE);
      return nullptr;
    }
  biom->type = type;
  return biom;
}

inline void BIO_meth_free(BIO_METHOD *biom)
{
  if (biom != nullptr)
    {
      OPENSSL_free((void *)biom->name);
      delete biom;
    }
}

inline void BIO_set_shutdown(BIO *a, int shut)
{
  a->shutdown = shut;
}

inline int BIO_get_shutdown(BIO *a)
{
  return a->shutdown;
}

inline void BIO_set_data(BIO *a, void *ptr)
{
  a->ptr = ptr;
}

inline void *BIO_get_data(BIO *a)
{
  return a->ptr;
}

inline void BIO_set_init(BIO *a, int init)
{
  a->init = init;
}

inline int BIO_get_init(BIO *a)
{
  return a->init;
}

inline int BIO_meth_set_write(BIO_METHOD *biom,
			      int (*bwrite)(BIO *, const char *, int))
{
  biom->bwrite = bwrite;
  return 1;
}

inline int BIO_meth_set_read(BIO_METHOD *biom,
			     int (*bread)(BIO *, char *, int))
{
  biom->bread = bread;
  return 1;
}

inline int BIO_meth_set_puts(BIO_METHOD *biom,
			     int (*bputs)(BIO *, const char *))
{
  biom->bputs = bputs;
  return 1;
}

inline int BIO_meth_set_gets(BIO_METHOD *biom,
			     int (*bgets)(BIO *, char *, int))
{
  biom->bgets = bgets;
  return 1;
}

inline int BIO_meth_set_ctrl(BIO_METHOD *biom,
			     long (*ctrl)(BIO *, int, long, void *))
{
  biom->ctrl = ctrl;
  return 1;
}

inline int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *))
{
  biom->create = create;
  return 1;
}

inline int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *))
{
  biom->destroy = destroy;
  return 1;
}
#endif