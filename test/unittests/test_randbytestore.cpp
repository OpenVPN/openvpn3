#include "test_common.hpp"

#include <cstdint>
#include <limits>
#include <vector>

#include <openvpn/random/randbytestore.hpp>

using namespace openvpn;

// A deterministic fake RNG satisfying the UniformRandomBitGenerator concept.
// Returns a fixed sequence of values supplied at construction.
template <typename T>
class FakeRNG
{
  public:
    using result_type = T;

    explicit FakeRNG(std::vector<T> values)
        : values_(std::move(values))
    {
    }

    static constexpr result_type min()
    {
        return std::numeric_limits<T>::min();
    }

    static constexpr result_type max()
    {
        return std::numeric_limits<T>::max();
    }

    result_type operator()()
    {
        EXPECT_LT(call_count_, values_.size()) << "FakeRNG called more times than expected";
        return values_[call_count_++];
    }

    size_t call_count() const
    {
        return call_count_;
    }

  private:
    std::vector<T> values_;
    size_t call_count_ = 0;
};

// Correct behaviour: bytes are extracted LSB-first from a 32-bit value.
TEST(randbytestore, get_byte_order_u32)
{
    FakeRNG<uint32_t> rng({0xDEADBEEF});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    EXPECT_EQ(rbs.get_byte(rng), 0xEF);
    EXPECT_EQ(rbs.get_byte(rng), 0xBE);
    EXPECT_EQ(rbs.get_byte(rng), 0xAD);
    EXPECT_EQ(rbs.get_byte(rng), 0xDE);

    // Exactly one RNG call for four bytes
    EXPECT_EQ(rng.call_count(), 1u);
}

// Correct behaviour: bytes are extracted LSB-first from a 64-bit value.
TEST(randbytestore, get_byte_order_u64)
{
    FakeRNG<uint64_t> rng({0x0102030405060708ULL});
    RandomByteStore<FakeRNG<uint64_t>> rbs;

    EXPECT_EQ(rbs.get_byte(rng), 0x08);
    EXPECT_EQ(rbs.get_byte(rng), 0x07);
    EXPECT_EQ(rbs.get_byte(rng), 0x06);
    EXPECT_EQ(rbs.get_byte(rng), 0x05);
    EXPECT_EQ(rbs.get_byte(rng), 0x04);
    EXPECT_EQ(rbs.get_byte(rng), 0x03);
    EXPECT_EQ(rbs.get_byte(rng), 0x02);
    EXPECT_EQ(rbs.get_byte(rng), 0x01);

    // Exactly one RNG call for eight bytes
    EXPECT_EQ(rng.call_count(), 1u);
}

// Correct behaviour: a second RNG call is made only after all bytes are consumed.
TEST(randbytestore, refill_on_exhaustion)
{
    FakeRNG<uint32_t> rng({0x11223344, 0xAABBCCDD});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    // Consume first word (4 bytes)
    for (int i = 0; i < 4; ++i)
        rbs.get_byte(rng);
    EXPECT_EQ(rng.call_count(), 1u);

    // First byte of second word triggers the refill
    EXPECT_EQ(rbs.get_byte(rng), 0xDD);
    EXPECT_EQ(rng.call_count(), 2u);
}

// Correct behaviour: fill() populates a struct with the expected bytes.
TEST(randbytestore, fill_struct)
{
    // Two successive 32-bit words: the fill covers exactly 8 bytes
    FakeRNG<uint32_t> rng({0x01020304, 0x05060708});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    uint64_t result = 0;
    rbs.fill(result, rng);

    // fill() writes bytes in get_byte() order (LSB-first per word)
    // Word 0: 0x01020304 → bytes 04 03 02 01 at offsets 0-3
    // Word 1: 0x05060708 → bytes 08 07 06 05 at offsets 4-7
    const unsigned char *b = reinterpret_cast<const unsigned char *>(&result);
    EXPECT_EQ(b[0], 0x04);
    EXPECT_EQ(b[1], 0x03);
    EXPECT_EQ(b[2], 0x02);
    EXPECT_EQ(b[3], 0x01);
    EXPECT_EQ(b[4], 0x08);
    EXPECT_EQ(b[5], 0x07);
    EXPECT_EQ(b[6], 0x06);
    EXPECT_EQ(b[7], 0x05);

    EXPECT_EQ(rng.call_count(), 2u);
}

// Incorrect behaviour: wrong byte order would be caught by this test.
TEST(randbytestore, byte_order_not_msb_first)
{
    FakeRNG<uint32_t> rng({0xAABBCCDD});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    // If extraction were MSB-first the first byte would be 0xAA — it must not be.
    EXPECT_NE(rbs.get_byte(rng), 0xAA);
}

// Incorrect behaviour: early refill would be caught — RNG must not be called twice
// for the first sizeof(result_type) bytes.
TEST(randbytestore, no_early_refill)
{
    FakeRNG<uint32_t> rng({0x12345678, 0xDEADBEEF});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    rbs.get_byte(rng);
    rbs.get_byte(rng);
    rbs.get_byte(rng);

    // Three bytes consumed from a 32-bit word — still only one RNG call
    EXPECT_EQ(rng.call_count(), 1u);
}

// Incorrect behaviour: a missed refill (stale data) would produce a zero byte
// where the new RNG value should appear.
TEST(randbytestore, no_missed_refill)
{
    FakeRNG<uint32_t> rng({0x00000000, 0xFF000000});
    RandomByteStore<FakeRNG<uint32_t>> rbs;

    for (int i = 0; i < 4; ++i)
        rbs.get_byte(rng);

    // Without a refill the 5th byte would be 0x00 (stale); with correct
    // behaviour the new word 0xFF000000 contributes 0x00 at byte 0 as well,
    // so use a value that makes the distinction unambiguous.
    FakeRNG<uint32_t> rng2({0x00000000, 0xABCDEF01});
    RandomByteStore<FakeRNG<uint32_t>> rbs2;

    for (int i = 0; i < 4; ++i)
        rbs2.get_byte(rng2);

    EXPECT_EQ(rbs2.get_byte(rng2), 0x01); // LSB of 0xABCDEF01
    EXPECT_EQ(rng2.call_count(), 2u);
}
