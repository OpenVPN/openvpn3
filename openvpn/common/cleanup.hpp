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

#ifndef OPENVPN_COMMON_CLEANUP_H
#define OPENVPN_COMMON_CLEANUP_H

#include <utility>
#include <optional>
#include <concepts>
#include <functional>
#include <type_traits>

namespace openvpn {

/**
 * @brief A scope guard that runs a callable on destruction unless dismissed or released.
 * @tparam F The type of the callable to run on destruction.
 * @details
 * The Cleanup class template provides a mechanism to ensure that a specified callable
 * is executed when the Cleanup object goes out of scope, unless it has been dismissed
 * or released. This is useful for resource management and cleanup tasks that need to
 * be performed when exiting a scope.
 * @todo Keep std::scope_exit in mind when moving to C++23.
 */
template <typename F>
    requires std::invocable<F>
class CleanupType
{
  public:
    explicit CleanupType(F method) noexcept(std::is_nothrow_move_constructible_v<F>)
        : clean(std::move(method))
    {
    }
    CleanupType(const CleanupType &) = delete;
    CleanupType &operator=(const CleanupType &) = delete;
    CleanupType(CleanupType &&other) noexcept
        : clean(std::exchange(other.clean, std::nullopt))
    {
    }
    CleanupType &operator=(CleanupType &&other) noexcept
    {
        if (this != &other)
        {
            clean = std::exchange(other.clean, std::nullopt);
        }
        return *this;
    }

    /**
     * @brief Destructor that executes the cleanup action if not dismissed or released.
     * @details When the CleanupType object is destroyed, if the cleanup action has not
     * been dismissed or released, it will be invoked. Any exceptions thrown by the
     * cleanup action are caught and swallowed to prevent exceptions from escaping the
     * destructor.
     */
    ~CleanupType() noexcept
    {
        if (clean)
        {
            try
            {
                std::invoke(*clean);
            }
            catch (...)
            {
                // swallow exceptions to avoid throwing from destructor
            }
        }
    }

  public:
    /**
     * @brief Dismiss the cleanup action, preventing it from being executed on destruction.
     * @details After calling dismiss, the cleanup action will not be invoked when the
     * CleanupType object is destroyed.
     */
    void dismiss() noexcept
    {
        clean.reset();
    }
    /**
     * @brief Release the cleanup action, returning the callable and preventing it from being
     * executed on destruction.
     * @return An optional containing the callable if it was set, or std::nullopt if it was
     * dismissed or already released.
     * @details After calling release, the cleanup action will not be invoked when the
     * CleanupType object is destroyed, and the caller takes ownership of the callable. This
     * allows the caller to manage the callable's lifetime independently, including calling it
     * earlier or later than it might be otherwise called.
     */
    std::optional<std::function<void()>> release() noexcept
    {
        if (clean)
        {
            std::function<void()> func = std::move(*clean);
            clean.reset();
            return func;
        }
        return std::nullopt;
    }

  private:
    std::optional<F> clean;
};

/**
 * @brief Factory function to create a CleanupType object.
 * @tparam F The type of the callable to run on destruction.
 * @param method The callable to be executed on destruction.
 * @return A CleanupType object that will execute the callable on destruction.
 * @details This function simplifies the creation of CleanupType objects by deducing
            the type of the callable and forwarding it to the CleanupType constructor.
 */
template <typename F>
    requires std::invocable<F>
inline CleanupType<F> Cleanup(F method) noexcept(std::is_nothrow_move_constructible_v<F>)
{
    return CleanupType<F>(std::move(method));
}

} // namespace openvpn

#endif
