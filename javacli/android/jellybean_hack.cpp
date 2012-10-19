//
//  rsasign.cpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Native companion code for JellyBeanHack.java

#include <stdio.h>
#include <dlfcn.h>
#include <jni.h>

#include <android/log.h>

#ifdef SWIGEXPORT
#define EXPORT SWIGEXPORT
#else
#define EXPORT
#endif

#ifdef PRIVATE_TUNNEL
#define RSA_SIGN_INIT Java_net_openvpn_privatetunnel_JellyBeanHack_rsa_1sign_1init
#define RSA_SIGN      Java_net_openvpn_privatetunnel_JellyBeanHack_rsa_1sign
#define PKEY_RETAIN   Java_net_openvpn_privatetunnel_JellyBeanHack_pkey_1retain
#else
#define RSA_SIGN_INIT Java_net_openvpn_openvpn_JellyBeanHack_rsa_1sign_1init
#define RSA_SIGN      Java_net_openvpn_openvpn_JellyBeanHack_rsa_1sign
#define PKEY_RETAIN   Java_net_openvpn_openvpn_JellyBeanHack_pkey_1retain
#endif

extern "C" {
  jint RSA_SIGN_INIT(JNIEnv* env, jclass);
  jbyteArray RSA_SIGN(JNIEnv* env, jclass, jbyteArray from, jint pkeyRef);
  void PKEY_RETAIN(JNIEnv* env, jclass, jint pkeyRef);
};

typedef void *RSA;

enum {
  NID_md5_sha1=114,
  CRYPTO_LOCK_EVP_PKEY=10,
};

struct EVP_PKEY
{
  int type;
  int save_type;
  int references;
  void *ameth;
  void *engine;
  union {
    RSA *rsa;
  } pkey;
};

typedef int (*RSA_size_func_t)(const RSA *);

typedef int (*RSA_sign_func_t)(int type, const unsigned char *m, unsigned int m_length,
			       unsigned char *sigret, unsigned int *siglen, RSA *rsa);

typedef void (*ERR_print_errors_fp_func_t)(FILE *fp);

typedef int (*CRYPTO_add_lock_func_t)(int *pointer, int amount, int type, const char *file, int line);

static bool initialized;
static RSA_size_func_t RSA_size;
static RSA_sign_func_t RSA_sign;
static ERR_print_errors_fp_func_t ERR_print_errors_fp;
static CRYPTO_add_lock_func_t CRYPTO_add_lock;

inline bool callbacks_defined()
{
  return RSA_size != NULL
    && RSA_sign != NULL
    && ERR_print_errors_fp != NULL
    && CRYPTO_add_lock != NULL;
}

EXPORT jint RSA_SIGN_INIT(JNIEnv* env, jclass)
{
  if (!initialized)
    {
      void *handle = dlopen("libcrypto.so", RTLD_NOW);
      if (handle)
	{
	  RSA_size =  (RSA_size_func_t) dlsym(handle, "RSA_size");
	  RSA_sign =  (RSA_sign_func_t) dlsym(handle, "RSA_sign");
	  ERR_print_errors_fp = (ERR_print_errors_fp_func_t) dlsym(handle, "ERR_print_errors_fp");
	  CRYPTO_add_lock =  (CRYPTO_add_lock_func_t) dlsym(handle, "CRYPTO_add_lock");
	}
      initialized = true;
    }
  return callbacks_defined();
}

static int jni_throw(JNIEnv* env, const char* className, const char* msg)
{
  jclass exceptionClass = env->FindClass(className);

  if (exceptionClass == NULL) {
    // ClassNotFoundException now pending
    return -1;
  }

  if (env->ThrowNew( exceptionClass, msg) != JNI_OK) {
    // an exception, most likely OOM, will now be pending
    return -1;
  }

  env->DeleteLocalRef(exceptionClass);
  return 0;
}

EXPORT jbyteArray RSA_SIGN(JNIEnv* env, jclass, jbyteArray from, jint pkeyRef)
{
  if (!callbacks_defined())
    {
      jni_throw(env, "java/lang/NullPointerException", "rsa_sign: OpenSSL callbacks undefined");
      return NULL;
    }

  EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(pkeyRef);
  if (pkey == NULL || from == NULL)
    {
      jni_throw(env, "java/lang/NullPointerException", "rsa_sign: from/pkey is NULL");
      return NULL;
    }

  jbyte* data =  env->GetByteArrayElements(from, NULL);
  if (data == NULL)
    {
      jni_throw(env, "java/lang/NullPointerException", "rsa_sign: data is NULL");
      return NULL;
    }
  int datalen = env->GetArrayLength(from);

  unsigned int siglen;
  unsigned char* sigret = new unsigned char[(*RSA_size)(pkey->pkey.rsa)];

  if ((*RSA_sign)(NID_md5_sha1, (unsigned char*) data, datalen,
		  sigret, &siglen, pkey->pkey.rsa) <= 0)
    {
      jni_throw(env, "java/security/InvalidKeyException", "OpenSSL RSA_sign failed");
      (*ERR_print_errors_fp)(stderr);
      return NULL;
    }

  jbyteArray jb = env->NewByteArray(siglen);
  env->SetByteArrayRegion(jb, 0, siglen, (jbyte *)sigret);
  delete [] sigret;
  return jb;
}

EXPORT void PKEY_RETAIN(JNIEnv* env, jclass, jint pkeyRef)
{
  EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(pkeyRef);
  if (pkey && CRYPTO_add_lock)
    {
      const int newref = (*CRYPTO_add_lock)(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY, __FILE__, __LINE__);
      __android_log_print(ANDROID_LOG_DEBUG, "openvpn", "pkey_retain ref=%d", newref);
    }
}
