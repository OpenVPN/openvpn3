#include "test_common.h"

#include <openvpn/buffer/bufstr.hpp>

using namespace openvpn;

// test equality of Buffer and ConstBuffer
TEST(buffer, const_buffer_ref_1)
{
    static unsigned char hello[] = "hello world";
    Buffer buf(hello, sizeof(hello) - 1, true);
    ConstBuffer &cbuf = const_buffer_ref(buf);
    ASSERT_EQ(cbuf.size(), 11);
    ASSERT_EQ(buf_to_string(buf), buf_to_string(cbuf));
}

// test equality of BufferAllocated and ConstBuffer
TEST(buffer, const_buffer_ref_2)
{
    BufferAllocated buf(64, 0);
    buf_append_string(buf, "hello world");
    ConstBuffer &cbuf = const_buffer_ref(buf);
    ASSERT_EQ(cbuf.size(), 11);
    ASSERT_EQ(buf_to_string(buf), buf_to_string(cbuf));
}

// test ConstBufferType with an explicitly const type
TEST(buffer, my_const_buffer_1)
{
    typedef ConstBufferType<const char> MyConstBuffer;
    static const char hello[] = "hello world";
    MyConstBuffer cbuf(hello, sizeof(hello) - 1, true);
    ASSERT_EQ(cbuf.size(), 11);
    ASSERT_EQ(std::string(cbuf.c_data(), cbuf.size()), "hello world");
}
