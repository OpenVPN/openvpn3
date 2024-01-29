//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2021-2022 OpenVPN Inc.
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

#include <iostream>

#include "test_common.h"

#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/crypto/crypto_aead.hpp>


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


void test_datachannel_crypto(bool tag_at_the_end, bool longpktcounter = false)
{

    auto frameptr = openvpn::Frame::Ptr{new openvpn::Frame{frame_ctx()}};
    auto statsptr = openvpn::SessionStats::Ptr{new openvpn::SessionStats{}};

    openvpn::CryptoDCSettingsData dc;
    dc.set_cipher(openvpn::CryptoAlgs::AES_256_GCM);
    dc.set_aead_tag_end(tag_at_the_end);
    dc.set_64_bit_packet_id(longpktcounter);

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

    cryptodc.init_pid(0,
                      "DATA",
                      0,
                      statsptr);

    openvpn::BufferAllocated work{2048, 0};

    /* reserve some headroom */
    work.realign(128);

    std::memcpy(work.write_alloc(std::strlen(plaintext)), plaintext, std::strlen(plaintext));
    const unsigned char *data = work.data();
    EXPECT_TRUE(std::memcmp(data, plaintext, std::strlen(plaintext)) == 0);

    const openvpn::PacketID::time_t now = 42;

    const unsigned char op32[]{7, 0, 0, 23};

    bool const wrapwarn = cryptodc.encrypt(work, now, op32);
    ASSERT_FALSE(wrapwarn);

    size_t pkt_counter_len = longpktcounter ? 8 : 4;
    size_t tag_len = 16;

    /* 16 for tag, 4 or 8 for packet counter */
    EXPECT_EQ(work.size(), std::strlen(plaintext) + pkt_counter_len + tag_len);

    const uint8_t exp_tag_short[16]{0x1f, 0xdd, 0x90, 0x8f, 0x0e, 0x9d, 0xc2, 0x5e, 0x79, 0xd8, 0x32, 0x02, 0x0d, 0x58, 0xe7, 0x3f};
    const uint8_t exp_tag_long[16]{0x52, 0xee, 0xef, 0xdb, 0x34, 0xb7, 0xbd, 0x79, 0xfe, 0xbf, 0x69, 0xd0, 0x4e, 0x92, 0xfe, 0x4b};

    const uint8_t *expected_tag;

    if (longpktcounter)
        expected_tag = exp_tag_long;
    else
        expected_tag = exp_tag_short;

    // Packet id/IV should 1
    if (longpktcounter)
    {
        uint8_t packetid1[]{0, 0, 0, 0, 0, 0, 0, 1};
        EXPECT_EQ(std::memcmp(work.data(), packetid1, 8), 0);
    }
    else
    {
        uint8_t packetid1[]{0, 0, 0, 1};
        EXPECT_EQ(std::memcmp(work.data(), packetid1, 4), 0);
    }


    // Tag is in the front after packet id
    if (tag_at_the_end)
    {
        EXPECT_EQ(std::memcmp(work.data() + 56 + pkt_counter_len, expected_tag, 16), 0);
    }
    else
    {
        EXPECT_EQ(std::memcmp(work.data() + pkt_counter_len, expected_tag, 16), 0);
    }

    // Check a few random bytes of the encrypted output. Different IVs lead to different output here.
    ptrdiff_t tagoffset = tag_at_the_end ? 0 : 16;
    if (longpktcounter)
    {
        const uint8_t bytesat14[6]{0xc7, 0x40, 0x47, 0x81, 0xac, 0x8c};
        EXPECT_EQ(std::memcmp(work.data() + tagoffset + 14, bytesat14, 6), 0);
    }
    else
    {
        const uint8_t bytesat14[6]{0xa8, 0x2e, 0x6b, 0x17, 0x06, 0xd9};
        EXPECT_EQ(std::memcmp(work.data() + tagoffset + 14, bytesat14, 6), 0);
    }

    /* Check now if decrypting also works */
    auto ret = cryptodc.decrypt(work, now, op32);

    EXPECT_EQ(ret, openvpn::Error::SUCCESS);
    EXPECT_EQ(work.size(), std::strlen(plaintext));

    EXPECT_EQ(std::memcmp(work.data(), plaintext, std::strlen(plaintext)), 0);
}


TEST(crypto, dcaead_tag_at_the_front)
{
    test_datachannel_crypto(false);
}

TEST(crypto, dcaead_tag_at_the_end)
{
    test_datachannel_crypto(true);
}


TEST(crypto, dcaead_tag_at_the_front_long_pktcntr)
{
    test_datachannel_crypto(false, true);
}

TEST(crypto, dcaead_tag_at_the_end_long_pktcntr)
{
    test_datachannel_crypto(true, true);
}
