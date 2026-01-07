#include "test_common.hpp"

#include <openvpn/common/cleanup.hpp>

#include <memory>
#include <stdexcept>
#include <vector>

using namespace openvpn;

TEST(Misc, Cleanup)
{
    bool ran_cleanup = false;
    {
        auto c = Cleanup([&]()
                         { ran_cleanup = true; });
        static_assert(std::is_nothrow_move_constructible<decltype(c)>::value,
                      "Cleanup should be noexcept MoveConstructible");
    }
    ASSERT_TRUE(ran_cleanup) << "cleanup didn't run as expected";
}

TEST(misc, cleanup_basic_execution)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
    }
    ASSERT_EQ(counter, 1) << "cleanup should execute once on scope exit";
}

TEST(misc, cleanup_multiple_guards)
{
    std::vector<int> execution_order;
    {
        auto c1 = Cleanup([&]()
                          { execution_order.push_back(1); });
        auto c2 = Cleanup([&]()
                          { execution_order.push_back(2); });
        auto c3 = Cleanup([&]()
                          { execution_order.push_back(3); });
    }
    ASSERT_EQ(execution_order.size(), 3);
    // Destructors run in reverse order
    ASSERT_EQ(execution_order[0], 3);
    ASSERT_EQ(execution_order[1], 2);
    ASSERT_EQ(execution_order[2], 1);
}

TEST(misc, cleanup_dismiss)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        c.dismiss();
    }
    ASSERT_EQ(counter, 0) << "cleanup should not execute after dismiss()";
}

TEST(misc, cleanup_dismiss_idempotent)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        c.dismiss();
        c.dismiss(); // Should be safe to call multiple times
        c.dismiss();
    }
    ASSERT_EQ(counter, 0) << "multiple dismiss() calls should be safe";
}

TEST(misc, cleanup_release)
{
    int counter = 0;
    std::optional<std::function<void()>> released;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        released = c.release();
    }
    ASSERT_EQ(counter, 0) << "cleanup should not execute after release()";
    ASSERT_TRUE(released.has_value()) << "release() should return the callable";

    // Manually invoke the released callable
    std::invoke(*released);
    ASSERT_EQ(counter, 1) << "released callable should still be invocable";
}

TEST(misc, cleanup_release_empty)
{
    int counter = 0;
    std::optional<std::function<void()>> released;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        c.dismiss();
        released = c.release();
    }
    ASSERT_EQ(counter, 0) << "cleanup should not execute";
    ASSERT_FALSE(released.has_value()) << "release() after dismiss() should return empty optional";
}

TEST(misc, cleanup_move_constructor)
{
    int counter = 0;
    {
        auto c1 = Cleanup([&counter]()
                          { ++counter; });
        auto c2 = std::move(c1);
        // c1 is now moved-from, c2 owns the cleanup
    }
    ASSERT_EQ(counter, 1) << "cleanup should execute once from moved-to object";
}

TEST(misc, cleanup_move_constructor_no_double_execute)
{
    int counter = 0;
    {
        auto c1 = Cleanup([&counter]()
                          { ++counter; });
        {
            auto c2 = std::move(c1);
        } // c2 destroyed here, should execute
    } // c1 destroyed here, should NOT execute
    ASSERT_EQ(counter, 1) << "cleanup should execute only once after move";
}

TEST(misc, cleanup_exception_swallowed)
{
    bool cleanup_started = false;
    try
    {
        auto c = Cleanup([&]()
                         {
            cleanup_started = true;
            throw std::runtime_error("exception in cleanup"); });
        // Destructor runs here when c goes out of scope
    }
    catch (...)
    {
        // Exception should NOT escape destructor
        FAIL() << "Exception should be swallowed by noexcept destructor";
    }
    ASSERT_TRUE(cleanup_started) << "cleanup should start executing";
}

TEST(misc, cleanup_noexcept_destructor)
{
    // Verify destructor is noexcept
    auto c = Cleanup([]() {});
    static_assert(std::is_nothrow_destructible_v<decltype(c)>, "Destructor should be noexcept");
}

TEST(misc, cleanup_with_mutable_lambda)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter, call_count = 0]() mutable
                         {
            ++call_count;
            counter = call_count; });
    }
    ASSERT_EQ(counter, 1) << "mutable lambda should work correctly";
}

TEST(misc, cleanup_with_captured_unique_ptr)
{
    bool deleted = false;
    struct Deleter
    {
        bool *flag;
        void operator()(int *p)
        {
            *flag = true;
            delete p;
        }
    };
    {
        std::unique_ptr<int, Deleter> ptr(new int(42), Deleter{&deleted});
        auto c = Cleanup([p = std::move(ptr)]() mutable
                         { p.reset(); });
    }
    ASSERT_TRUE(deleted) << "unique_ptr should be properly moved and deleted";
}

TEST(misc, cleanup_concept_constraint)
{
    // Should compile with invocable types
    auto c1 = Cleanup([]() {});
    auto c2 = Cleanup(std::function<void()>([]() {}));

    struct Callable
    {
        void operator()() const
        {
        }
    };
    auto c3 = Cleanup(Callable{});

    // Should NOT compile with non-invocable types (uncomment to test)
    // auto c4 = Cleanup(42); // Error: does not satisfy std::invocable
}

TEST(misc, cleanup_dismiss_then_destroy)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        c.dismiss();
        // Additional operations after dismiss
        ASSERT_EQ(counter, 0);
    }
    ASSERT_EQ(counter, 0) << "dismissed cleanup should not execute on destruction";
}

TEST(misc, cleanup_factory_function)
{
    int counter = 0;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        // Just verify it compiles and works - type checking is implementation detail
    }
    ASSERT_EQ(counter, 1);
}

TEST(misc, cleanup_return_from_function)
{
    int counter = 0;
    auto make_cleanup = [&counter]()
    {
        return Cleanup([&counter]()
                       { ++counter; });
    };
    {
        auto c = make_cleanup();
    }
    ASSERT_EQ(counter, 1) << "cleanup returned from function should work";
}

TEST(misc, cleanup_nested_scopes)
{
    std::vector<int> order;
    {
        auto c1 = Cleanup([&]()
                          { order.push_back(1); });
        {
            auto c2 = Cleanup([&]()
                              { order.push_back(2); });
            {
                auto c3 = Cleanup([&]()
                                  { order.push_back(3); });
            }
        }
    }
    ASSERT_EQ(order.size(), 3);
    ASSERT_EQ(order[0], 3);
    ASSERT_EQ(order[1], 2);
    ASSERT_EQ(order[2], 1);
}

TEST(misc, cleanup_conditional_dismiss)
{
    int counter = 0;
    bool should_cleanup = false;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        if (!should_cleanup)
        {
            c.dismiss();
        }
    }
    ASSERT_EQ(counter, 0);

    should_cleanup = true;
    {
        auto c = Cleanup([&counter]()
                         { ++counter; });
        if (!should_cleanup)
        {
            c.dismiss();
        }
    }
    ASSERT_EQ(counter, 1);
}
