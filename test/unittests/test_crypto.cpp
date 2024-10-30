//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2021- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include <iostream>

#include "test_common.hpp"

#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/crypto/crypto_aead.hpp>
#include <openvpn/crypto/data_epoch.hpp>


static uint8_t testkey[20] = {0x0b, 0x00};
static uint8_t goodhash[20] = {
    // clang-format off
    0x58, 0xea, 0x5a, 0xf0, 0x42, 0x94, 0xe9, 0x17,
    0xed, 0x84, 0xb9, 0xf0, 0x83, 0x30, 0x23, 0xae,
    0x8b, 0xa7, 0x7e, 0xb8
    // clang-format on
};

static const char *ipsumlorem = "Lorem ipsum dolor sit amet, consectetur "
                                "adipisici elit, sed eiusmod tempor incidunt "
                                "ut labore et dolore magna aliqua.";

TEST(crypto, hmac)
{
    uint8_t key[20];
    std::memcpy(key, testkey, sizeof(key));

    openvpn::SSLLib::CryptoAPI::HMACContext hmac(openvpn::CryptoAlgs::SHA1, key, sizeof(key));

    const uint8_t *ipsum = reinterpret_cast<const uint8_t *>(ipsumlorem);

    hmac.update(ipsum, std::strlen(ipsumlorem));
    hmac.update(ipsum, std::strlen(ipsumlorem));

    uint8_t hash[20];

    ASSERT_EQ(hmac.final(hash), 20u);

    /* Google test does not seem to have a good memory equality test macro */
    ASSERT_EQ(std::memcmp(hash, goodhash, sizeof(goodhash)), 0);

    hmac.reset();

    /* Do this again to ensure that reset works */
    hmac.update(ipsum, std::strlen(ipsumlorem));
    hmac.update(ipsum, std::strlen(ipsumlorem));
    ASSERT_EQ(hmac.final(hash), 20u);

    /* Google test does not seem to have a good memory equality test macro */
    ASSERT_EQ(std::memcmp(hash, goodhash, sizeof(goodhash)), 0);

    /* Overwrite the key to ensure that the memory is no referenced by internal
     * structs of the hmac */
    std::memset(key, 0x55, sizeof(key));

    hmac.reset();

    /* Do this again to ensure that reset works */
    hmac.update(ipsum, std::strlen(ipsumlorem));
    hmac.update(ipsum, std::strlen(ipsumlorem));
    ASSERT_EQ(hmac.final(hash), 20u);

    /* Google test does not seem to have a good memory equality test macro */
    ASSERT_EQ(std::memcmp(hash, goodhash, sizeof(goodhash)), 0);
}

static openvpn::Frame::Context frame_ctx()
{
    const size_t payload = 2048;
    const size_t headroom = 64;
    const size_t tailroom = 64;
    const size_t align_block = 16;
    const unsigned int buffer_flags = 0;
    return openvpn::Frame::Context{headroom, payload, tailroom, 0, align_block, buffer_flags};
}


void test_datachannel_crypto(bool use_epoch)
{

    auto frameptr = openvpn::Frame::Ptr{new openvpn::Frame{frame_ctx()}};
    auto statsptr = openvpn::SessionStats::Ptr{new openvpn::SessionStats{}};

    openvpn::CryptoDCSettingsData dc;
    dc.set_cipher(openvpn::CryptoAlgs::AES_256_GCM);
    dc.set_use_epoch_keys(use_epoch);

    openvpn::AEAD::Crypto<openvpn::SSLLib::CryptoAPI> cryptodc{nullptr, dc, frameptr, statsptr};

    const char *plaintext = "The quick little fox jumps over the bureaucratic hurdles";

    const uint8_t key[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', '0', '1', '2', '3', '4', '5', '6', '7', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'j', 'k', 'u', 'c', 'h', 'e', 'n', 'l'};

    static_assert(sizeof(key) == 32, "Size of key should be 32 bytes");

    /* copy the key a few times to ensure to have the size we need for
     * Statickey but XOR it to not repeat it */
    uint8_t bigkey[openvpn::OpenVPNStaticKey::KEY_SIZE]{};

    for (int i = 0; i < openvpn::OpenVPNStaticKey::KEY_SIZE; i++)
    {
        bigkey[i] = static_cast<uint8_t>(key[i % sizeof(key)] ^ i);
    }

    openvpn::OpenVPNStaticKey static_key;
    std::memcpy(static_key.raw_alloc(), bigkey, sizeof(bigkey));

    auto key_dir = openvpn::OpenVPNStaticKey::NORMAL;

    /* We here make encrypt and decrypt keys the same by design to have the loopback decryption capability */
    cryptodc.init_hmac(static_key.slice(openvpn::OpenVPNStaticKey::HMAC | openvpn::OpenVPNStaticKey::ENCRYPT | key_dir),
                       static_key.slice(openvpn::OpenVPNStaticKey::HMAC | openvpn::OpenVPNStaticKey::ENCRYPT | key_dir));

    cryptodc.init_cipher(static_key.slice(openvpn::OpenVPNStaticKey::CIPHER | openvpn::OpenVPNStaticKey::ENCRYPT | key_dir),
                         static_key.slice(openvpn::OpenVPNStaticKey::CIPHER | openvpn::OpenVPNStaticKey::ENCRYPT | key_dir));

    cryptodc.init_pid("DATA",
                      0,
                      statsptr);

    openvpn::BufferAllocated work{2048, 0};

    /* reserve some headroom */
    work.realign(128);

    std::memcpy(work.write_alloc(std::strlen(plaintext)), plaintext, std::strlen(plaintext));
    const unsigned char *data = work.data();
    EXPECT_TRUE(std::memcmp(data, plaintext, std::strlen(plaintext)) == 0);

    const std::time_t now = 42;

    const unsigned char op32[]{7, 0, 0, 23};

    bool const wrapwarn = cryptodc.encrypt(work, op32);
    ASSERT_FALSE(wrapwarn);

    size_t pkt_counter_len = use_epoch ? 8 : 4;
    size_t tag_len = 16;

    /* 16 for tag, 4 or 8 for packet counter */
    EXPECT_EQ(work.size(), std::strlen(plaintext) + pkt_counter_len + tag_len);

    const uint8_t exp_tag_short[16]{0x1f, 0xdd, 0x90, 0x8f, 0x0e, 0x9d, 0xc2, 0x5e, 0x79, 0xd8, 0x32, 0x02, 0x0d, 0x58, 0xe7, 0x3f};
    const uint8_t exp_tag_long[16]{0x52, 0xee, 0xef, 0xdb, 0x34, 0xb7, 0xbd, 0x79, 0xfe, 0xbf, 0x69, 0xd0, 0x4e, 0x92, 0xfe, 0x4b};


    if (use_epoch)
    {
        ptrdiff_t tag_offset = 56;
        uint8_t packetid1[]{0, 0, 0, 0, 0, 0, 0, 1};
        EXPECT_EQ(std::memcmp(work.data(), packetid1, 8), 0);
        EXPECT_EQ(std::memcmp(work.data() + tag_offset + pkt_counter_len, exp_tag_long, 16), 0);

        // Check a few random bytes of the encrypted output. Different IVs lead to different output here.
        const uint8_t bytesat14[6]{0xc7, 0x40, 0x47, 0x81, 0xac, 0x8c};
        EXPECT_EQ(std::memcmp(work.data() + 14, bytesat14, 6), 0);
    }
    else
    {
        ptrdiff_t tag_offset = 16;
        uint8_t packetid1[]{0, 0, 0, 1};
        EXPECT_EQ(std::memcmp(work.data(), packetid1, 4), 0);
        EXPECT_EQ(std::memcmp(work.data() + pkt_counter_len, exp_tag_short, 16), 0);

        // Check a few random bytes of the encrypted output. Different IVs lead to different output here.
        const uint8_t bytesat14[6]{0xa8, 0x2e, 0x6b, 0x17, 0x06, 0xd9};
        EXPECT_EQ(std::memcmp(work.data() + tag_offset + 14, bytesat14, 6), 0);
    }


    /* Check now if decrypting also works */
    auto ret = cryptodc.decrypt(work, now, op32);

    EXPECT_EQ(ret, openvpn::Error::SUCCESS);
    EXPECT_EQ(work.size(), std::strlen(plaintext));

    EXPECT_EQ(std::memcmp(work.data(), plaintext, std::strlen(plaintext)), 0);
}


TEST(crypto, dcaead_data_v2)
{
    test_datachannel_crypto(false);
}

TEST(crypto, dcaead_epoch_data)
{
    /* Epoch data needs more refactoring before adjusting the unit test */
    GTEST_SKIP();
    test_datachannel_crypto(true);
}

TEST(crypto, hkdf_expand_testa1)
{
    /* RFC 5889 A.1 Test Case 1 */
    // clang-format off
    uint8_t prk[32] =
        {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    uint8_t info[10] =
        {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
         0xf6, 0xf7, 0xf8, 0xf9};

    std::array<uint8_t,42> okm
        {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
         0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
         0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
         0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
         0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
         0x58, 0x65};
    // clang-format on


    std::array<uint8_t, 42> out{};
    openvpn::ovpn_hkdf_expand(prk, info, static_cast<int>(sizeof(info)), out.data(), static_cast<int>(out.size()));

    ASSERT_EQ(out, okm);
}

TEST(crypto, hkdf_expand_testa2)
{
    // clang-format off
    /* RFC 5889 A.2 Test Case 2 */
    uint8_t prk[32] =
        {0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
         0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
         0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
         0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44};

    uint8_t info[80] =
        {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
         0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
         0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
         0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
         0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
         0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
         0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
         0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
         0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
         0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    const int L = 82;
    std::array<uint8_t,82> okm
        {0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
         0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
         0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
         0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
         0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
         0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
         0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
         0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
         0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
         0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
         0x1d, 0x87};
    // clang-format on

    ASSERT_EQ(L, okm.size());
    std::array<uint8_t, 82> out = {0xaa};
    openvpn::ovpn_hkdf_expand(prk, info, static_cast<std::uint16_t>(sizeof(info)), out.data(), static_cast<std::uint16_t>(out.size()));


    ASSERT_EQ(out, okm);
}

TEST(crypto, ovpn_label_expand_test)
{
    // clang-format off
    uint8_t secret[32] =
        {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};

    std::array<uint8_t, 16> out_expected =
        {0x18, 0x5e, 0xaa, 0x1c, 0x7f, 0x22, 0x8a, 0xb8,
         0xeb, 0x29, 0x77, 0x32, 0x14, 0xd9, 0x20, 0x46};
    // clang-format on

    const uint8_t *label = reinterpret_cast<const uint8_t *>("unit test");
    std::array<uint8_t, 16> out;
    openvpn::ovpn_expand_label(secret, sizeof(secret), label, 9, nullptr, 0, out.data(), out.size());

    EXPECT_EQ(out, out_expected);
}

TEST(crypto, hkdf_expand_testa3)
{
    /* RFC 5889 A.3 Test Case 3 */
    // clang-format off
    uint8_t prk[32] =
        {0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16,
         0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
         0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77,
         0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04};

    std::array<uint8_t,42> okm =
        {0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
         0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
         0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
         0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
         0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
         0x96, 0xc8};
    // clang-format off

    uint8_t *info = nullptr;
    int L = 42;

    std::array<uint8_t,42>  out {0xfa};
    openvpn::ovpn_hkdf_expand(prk, info, 0, out.data(), L);

    ASSERT_EQ(out, okm);
}
