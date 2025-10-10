//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2024- OpenVPN Inc.
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

#pragma once

#include <optional> // std::nullopt_t
#include <stdexcept>
#include <type_traits>

namespace openvpn {

/**
    @brief designed to represent an optional reference to an object of type T
    @tparam T reference type
    @details This code defines a template class called optional<T&> which is designed to
    represent an optional reference to an object of type T. The purpose of this class is
    to provide a way to handle situations where a reference might or might not be
    available, similar to how std::optional works for regular types.

    The class doesn't take any direct inputs, but it can be instantiated with either no
    arguments (creating an empty optional), a reference to an object of type T, or
    another optional object. It produces an object that can either hold a reference to
    a T object or be empty.

    The class achieves its purpose by using a pointer (T *mRef) internally to store the
    address of the referenced object. When the optional is empty, this pointer is set to
    nullptr. The class provides various methods to check if a reference is present,
    access the referenced object, and assign new references or clear the optional.

    The important logic flows in this class include:

    - Constructors and assignment operators that allow creating and modifying the optional
      object. Assigning from T will write thru, modifying the T that is referred to. Assigning
      from another optional will change the target of the reference. Assigning std::nullopt
      will remove the reference target.
    - A boolean conversion operator that checks if the optional contains a valid reference.
    - Dereference operators (* and ->) that provide access to the referenced object, throwing
      an exception if the optional is empty. For example when calling the * operator, a check
      is done if the optional contains a valid reference. If it does, it returns the
      referenced object. If it doesn't, it throws an exception with the message
      "optional<T &>: access error".
    - The value and value_or members behave similarly except they return a copy of the stored
      value and in the case of value_or, the default is returned if the reference is not
      valid. This return by value is a bit idiosyncratic but they are provided for
      compatibility with the std::optional interface. Hopefully the function names serve as
      a reminder that the return is a value.

    This implementation allows programmers to work with optional references in a way
    that's similar to how they would work with optional values. It provides a slightly safer
    alternative to using raw pointers or references when dealing with objects that may or
    may not be available at runtime. The safety improvement is only that:

    - A segfault is prevented if the optional is de-refed while empty, substituting an
      exception that can be caught and handled instead.
    - Makes the code a little more self documenting in that a raw pointer is versatile
      and therefore might be used for many reasons, whereas this class is very specifically
      for representing an optional reference.
*/

template <typename T>
    requires std::is_reference_v<T>
class optional
{
    using value_type = std::remove_reference_t<T>;
    value_type *mRef = nullptr;
    static constexpr char errorMsg[] = "optional<T &>: access error";

  public:
    /**
     * @brief Default constructor. Creates an empty optional.
     */
    constexpr optional() noexcept = default;

    /**
     * @brief Constructs an empty optional.
     * @param noOption Indicates that the optional should be empty.
     */
    constexpr optional(std::nullopt_t noOption) noexcept;

    /**
     * @brief Constructs an optional containing a reference to the given object.
     * @param r Reference to the object to be stored.
     */
    constexpr optional(T r) noexcept;

    /**
     * @brief Constructs an optional containing a reference to the given object.
     * @param r pointer to the object to be stored.
     */
    constexpr optional(value_type *r) noexcept;

    /**
     * @brief Copy constructor.
     */
    constexpr optional(const optional &) noexcept = default;

    /**
     * @brief Move constructor.
     */
    constexpr optional(optional &&) noexcept = default;

    /**
     * @brief Copy assignment operator.
     * @return Reference to this object.
     */
    optional &operator=(const optional &) noexcept = default;

    /**
     * @brief Move assignment operator.
     * @return Reference to this object.
     */
    optional &operator=(optional &&) noexcept = default;

    /**
     * @brief Assigns the optional to be empty.
     * @param noOption Indicates that the optional should be empty.
     * @return Reference to this object.
     */
    optional &operator=(std::nullopt_t noOption) noexcept;

    /**
     * @brief Resets the optional, making it empty.
     */
    void reset() noexcept;

    /**
     * @brief Checks whether the optional contains a value.
     * @return true if the optional contains a value, false otherwise.
     */
    [[nodiscard]] constexpr bool has_value() const noexcept;

    /**
     * @brief Checks whether the optional contains a value.
     * @return true if the optional contains a value, false otherwise.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept;

    /**
     * @brief Gets the contained value.
     * @return Copy of the contained value.
     * @throws std::runtime_error if the optional is empty.
     */
    constexpr value_type value() const;

    /**
     * @brief Returns the contained value if the optional is not empty, otherwise
     *        returns the provided default value.
     * @param default_value The value to return if the optional is empty.
     * @return Copy of the contained value if the optional is not empty,
     *         otherwise a copy of the default value.
     */
    constexpr value_type value_or(const value_type &default_value) const noexcept;

    /**
     * @brief Dereference operator.
     * @return Const reference to the contained value.
     * @throws std::runtime_error if the optional is empty.
     */
    const T operator*() const;

    /**
     * @brief Dereference operator.
     * @return Reference to the contained value.
     * @throws std::runtime_error if the optional is empty.
     */
    T operator*();

    /**
     * @brief Arrow operator.
     * @return Const pointer to the contained value.
     * @throws std::runtime_error if the optional is empty.
     */
    const value_type *operator->() const;

    /**
     * @brief Arrow operator.
     * @return Pointer to the contained value.
     * @throws std::runtime_error if the optional is empty.
     */
    value_type *operator->();
};

// Implementations below

template <typename T>
    requires std::is_reference_v<T>
inline constexpr optional<T>::optional(std::nullopt_t) noexcept
    : optional()
{
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr optional<T>::optional(T r) noexcept
    : mRef(&r)
{
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr optional<T>::optional(value_type *r) noexcept
    : mRef(r)
{
}

template <typename T>
    requires std::is_reference_v<T>
inline optional<T> &optional<T>::operator=(std::nullopt_t) noexcept
{
    reset();
    return *this;
}

template <typename T>
    requires std::is_reference_v<T>
inline void optional<T>::reset() noexcept
{
    mRef = nullptr;
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr bool optional<T>::has_value() const noexcept
{
    return mRef != nullptr;
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr optional<T>::operator bool() const noexcept
{
    return has_value();
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr auto optional<T>::value() const -> value_type
{
    if (!bool(*this))
        throw std::runtime_error(errorMsg);
    return *mRef;
}

template <typename T>
    requires std::is_reference_v<T>
inline constexpr auto optional<T>::value_or(const value_type &default_value) const noexcept -> value_type
{
    return bool(*this) ? *mRef : default_value;
}

template <typename T>
    requires std::is_reference_v<T>
inline const T optional<T>::operator*() const
{
    if (!bool(*this))
        throw std::runtime_error(errorMsg);
    return *mRef;
}

template <typename T>
    requires std::is_reference_v<T>
inline T optional<T>::operator*()
{
    return const_cast<T &>(*(std::as_const(*this)));
}

template <typename T>
    requires std::is_reference_v<T>
inline auto optional<T>::operator->() const -> const value_type *
{
    if (!bool(*this))
        throw std::runtime_error(errorMsg);
    return mRef;
}

template <typename T>
    requires std::is_reference_v<T>
inline auto optional<T>::operator->() -> value_type *
{
    return const_cast<value_type *>(std::as_const(*this).operator->());
}

} // namespace openvpn
