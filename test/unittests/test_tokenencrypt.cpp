#include "test_common.h"

#include <iostream>
#include <cstring>

#include <openvpn/openssl/util/tokenencrypt.hpp>
#include <openvpn/ssl/sslchoose.hpp>

using namespace openvpn;

#ifndef ITER
#define ITER 1000
#endif

static void tryit(RandomAPI& rng, TokenEncryptDecrypt& encdec)
{
  std::uint8_t data1[TokenEncrypt::Key::SIZE];
  std::uint8_t data2[TokenEncrypt::Key::SIZE];
  std::uint8_t data3[TokenEncrypt::Key::SIZE];

  rng.rand_bytes(data1, sizeof(data1));
  encdec.encrypt(data2, data1, TokenEncrypt::Key::SIZE);
  encdec.decrypt(data3, data2, TokenEncrypt::Key::SIZE);
  ASSERT_TRUE(  ::memcmp(data1, data3, TokenEncrypt::Key::SIZE)== 0);
}

TEST(misc, tokenEncrypt)
{
  RandomAPI::Ptr rng(new SSLLib::RandomAPI(false));
  const TokenEncrypt::Key key(*rng);
  TokenEncryptDecrypt encdec(key);

  for (size_t i = 0; i < ITER; ++i)
    tryit(*rng, encdec);
}
