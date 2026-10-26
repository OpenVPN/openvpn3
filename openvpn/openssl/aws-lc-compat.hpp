//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#pragma once

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


#define BIO_F_MEM_WRITE 0
#define BIO_F_MEM_READ 0
#define BIOerr(f, r) ERR_put_error(ERR_LIB_BIO, (f), (r), __FILE__, __LINE__)

#define EVP_PKEY_DSA1 (-101)
#define EVP_PKEY_DSA2 (-102)
#define EVP_PKEY_DSA3 (-103)
#define EVP_PKEY_DSA4 (-104)

/* AWS-LC's GCM reads a NULL input as "finalize", so empty AAD/data (in=NULL, inl=0)
 * would prematurely compute the tag. Substitute a valid zero length buffer so it
 * stays a no-op. */
static inline int
EVP_EncryptUpdate_wrapper(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    static unsigned char empty_buf[1] = {0};
    if (inl == 0 && in == nullptr)
        in = empty_buf;
    return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}
#define EVP_EncryptUpdate EVP_EncryptUpdate_wrapper

static inline int
EVP_DecryptUpdate_wrapper(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    static unsigned char empty_buf[1] = {0};
    if (inl == 0 && in == nullptr)
        in = empty_buf;
    return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}
#define EVP_DecryptUpdate EVP_DecryptUpdate_wrapper


/* AWS-LC has no RSA_set_app_data or RSA_get_app_data. Re-provide them so a
 * pointer can be attached to an RSA object and read back later. */
static inline int RSA_app_data_index()
{
    static int idx = RSA_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return idx;
}

static inline int RSA_set_app_data(RSA *rsa, void *data)
{
    return RSA_set_ex_data(rsa, RSA_app_data_index(), data);
}

static inline void *RSA_get_app_data(const RSA *rsa)
{
    return RSA_get_ex_data(rsa, RSA_app_data_index());
}

/* AWS-LC defines EC_KEY_METHOD_set_sign as a macro that static_asserts
 * |sign_setup| == NULL. Override it to accept and drop |sign_setup| instead. */
static inline void
EC_KEY_METHOD_set_sign_wrapper(
    EC_KEY_METHOD *meth,
    int (*sign)(int type, const unsigned char *dgst, int dlen,
                unsigned char *sig, unsigned int *siglen,
                const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey),
    int (*)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinvp, BIGNUM **rp),
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey))
{
    EC_KEY_METHOD_set_sign_awslc(meth, sign, sign_sig);
}
#undef EC_KEY_METHOD_set_sign
#define EC_KEY_METHOD_set_sign EC_KEY_METHOD_set_sign_wrapper

/* AWS-LC's PKCS7_verify rejects a NULL store even under PKCS7_NOVERIFY, where it
 * goes unused. Pass an empty store when none is given. */
static inline int
PKCS7_verify_wrapper(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store, BIO *indata, BIO *out, int flags)
{
    static X509_STORE *empty_store = X509_STORE_new();
    return PKCS7_verify(p7, certs, store ? store : empty_store, indata, out, flags);
}
#define PKCS7_verify PKCS7_verify_wrapper

static inline bool
CRYPTO_tls1_prf_wrapper(unsigned char *out,
                        size_t out_len,
                        const unsigned char *secret,
                        size_t secret_len,
                        const unsigned char *label,
                        size_t label_len)
{
    return CRYPTO_tls1_prf(EVP_md5_sha1(),
                           out, out_len,
                           secret, secret_len,
                           reinterpret_cast<const char *>(label), label_len,
                           nullptr, 0,
                           nullptr, 0)
           == 1;
}
