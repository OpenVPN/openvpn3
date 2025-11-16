#include "test_common.hpp"

#include <openvpn/common/make_rc.hpp>

using namespace openvpn;

// Tests the RcEnable and make_rc functionality.

struct test1
{
    int i = 0;
};

using rc_test1 = RcEnable<test1>;

// The `f_ptr` function checks that the reference-counted object has the expected value.
void f_ptr(rc_test1::Ptr rct1, int i)
{
    EXPECT_EQ(rct1->i, i);
}

// Ref to base
void f_ref(test1 &t1, int i)
{
    EXPECT_EQ(t1.i, i);
}

// Sliced value
void f_val(test1 t1, int i)
{
    EXPECT_EQ(t1.i, i);
}

// The `direct_enable` test verifies that an RcEnable object can be created directly.
TEST(MakeRc, DirectEnable)
{
    auto rct1 = RcEnable<test1>::Create();
    EXPECT_EQ(rct1->i, 0);
}

// The `simple` test verifies that a reference-counted object can be created using `make_rc`.
TEST(MakeRc, Simple)
{
    auto rct1 = make_rc<test1>();
    EXPECT_EQ(rct1->i, 0);
}

// The `move_init` test verifies that a reference-counted object can be created by moving an existing object.
TEST(MakeRc, MoveInit)
{
    auto t = test1();
    EXPECT_EQ(t.i, 0);
    t.i = 42;
    auto rct1 = make_rc<test1>(std::move(t));
    EXPECT_EQ(rct1->i, 42);
}

// The `move_init_call` test verifies that a reference-counted object can be created by moving an existing object
// and passed to a function.
TEST(MakeRc, MoveInitCall)
{
    auto t = test1();
    EXPECT_EQ(t.i, 0);
    t.i = 42;
    f_ptr(make_rc<test1>(std::move(t)), 42);
}

// Calls using ref
TEST(MakeRc, CallValue)
{
    auto rct1 = RcEnable<test1>::Create();
    f_ref(*rct1, 0);
}

// Calls using sliced value
TEST(MakeRc, CallSlice)
{
    auto rct1 = RcEnable<test1>::Create();
    f_val(*rct1, 0);
}

// make_rc TS
TEST(MakeRc, SimpleTs)
{
    auto rct1 = make_rc<test1, RC<thread_safe_refcount>>();
    EXPECT_EQ(rct1->i, 0);
}
