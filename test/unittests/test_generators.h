#ifndef TEST_GENERATORS_H
#define TEST_GENERATORS_H
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion" // turn off warning for rapidcheck
#endif
#include <rapidcheck/gtest.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include <algorithm>

#include "openvpn/addr/ip.hpp"
#include "openvpn/tun/builder/capture.hpp"

namespace rc {

/**
 * @brief Generates an array of booleans that contains at least one \c false.
 * @details This template function generates an array of booleans of size \p N
 *          such that at least one of the elements in the array is \c false.
 * @tparam N The size of the array to be generated.
 * @return A generator that produces array where at least one boolean value is \c false.
 *
 * Example usage:
 * @code
 * auto falseBoolean = *atLeastOneFalse<5>();
 * @endcode
 */
template <size_t N>
auto atLeastOneFalse() -> Gen<std::array<bool, N>>
{
    static_assert(N > 0, "N must be greater than 0");

    return gen::suchThat(
        gen::container<std::array<bool, N>>(gen::arbitrary<bool>()),
        [](const auto &booleans)
        {
            return std::any_of(booleans.begin(), booleans.end(), [](const bool b)
                               { return !b; });
        });
}

/**
 * @brief Generates a valid or invalid IPv4 octet value.
 * @details This function generates a value that represents an IPv4 octet. If \p valid is \c true,
 * it generates a value within the valid range of 0 to 255. If \p valid is \c false, it generates
 * values outside this range to represent an invalid octet.
 * @param valid A boolean flag indicating whether to generate a valid or invalid octet value. Default is \c true.
 * @return A generator producing either valid IPv4 octet value (0-255) or invalid value.
 *
 * Example usage:
 * @code
 * auto octet = *IPv4Octet();
 * @endcode
 */
inline auto IPv4Octet(const bool valid = true) -> Gen<int>
{
    static constexpr int min_ipv4_octet = 0;
    static constexpr int max_ipv4_octet = 255;

    if (valid)
    {
        return gen::inRange(min_ipv4_octet, max_ipv4_octet + 1);
    }
    return gen::suchThat(gen::arbitrary<int>(), [](const auto &i)
                         { return i < min_ipv4_octet || i > max_ipv4_octet; });
}

/**
 * @brief Generates a random IPv4 address.
 * @details This function generates a random IPv4 address. The validity of the octets
 * can be controlled by the \p valid parameter. If \p valid is \c true, all four
 * octets will be valid. Otherwise, at least one octet will be invalid.
 * The resulting IPv4 address is formatted as \c X.X.X.X where \c X is a number between
 * 0 and 255 (or an invalid value if \p valid is \c false).
 * @param valid A boolean flag indicating whether the generated address should be valid.
 *              Defaults to \c true.
 * @return A generator producing either valid on invalid IPv4 address.
 *
 * Example usage:
 * @code
 * auto address = *IPv4Address();
 * @endcode
 */
inline auto IPv4Address(const bool valid = true) -> Gen<std::string>
{
    static constexpr int octets_number = 4;
    static constexpr std::array<bool, octets_number> all_true = {true, true, true, true};
    const auto octet_validity = valid ? all_true : *atLeastOneFalse<octets_number>().as("first,second,third,fourth octet valid");

    return gen::map(
        gen::tuple(IPv4Octet(octet_validity[0]),
                   IPv4Octet(octet_validity[1]),
                   IPv4Octet(octet_validity[2]),
                   IPv4Octet(octet_validity[3])),
        [](const auto &octets)
        {
            return std::to_string(std::get<0>(octets)) + "." + std::to_string(std::get<1>(octets)) + "."
                   + std::to_string(std::get<2>(octets)) + "." + std::to_string(std::get<3>(octets));
        });
}

/**
 * @brief Generates a random printable ASCII character code.
 * @details This function generates an integer value representing printable ASCII character,
 * ranging from 32 (space) to 126 (tilde).
 * @return A generator producing printable ASCII character code.
 *
 * Example usage:
 * @code
 * auto code = *asciiPrintableCode();
 * @endcode
 */
inline auto asciiPrintableCode() -> Gen<int>
{
    static constexpr int ASCII_range_start_code = 32; // ASCII code for space character
    static constexpr int ASCII_range_end_code = 127;  // ASCII code for DEL (not included)

    return gen::inRange(ASCII_range_start_code, ASCII_range_end_code);
}

/**
 * @brief Generates a valid or invalid hexadecimal character.
 * @details This function generates a single hexadecimal character. If \p valid is \c true,
 *          it generates a value within the valid ranges of \c 0-9, \c A-F, and \c a-f.
 *          If \p valid is \c false, it generates a character outside of these ranges to represent
 *          an invalid hexadecimal character.
 * @param valid A boolean flag indicating whether to generate a valid or invalid hexadecimal character.
 *              Default is \c true.
 * @return A generator producing either valid or invalid hexadecimal character.
 *
 * Example usage:
 * @code
 * auto hex_generator = *hexChar();
 * @endcode
 */
inline auto hexChar(const bool valid = true) -> Gen<std::string>
{
    if (valid)
    {
        static constexpr int ASCII_zero_position = 48; // '0'
        static constexpr int ASCII_nine_position = 57; // '9'
        const auto numbers = gen::inRange(ASCII_zero_position, ASCII_nine_position + 1);

        static constexpr int ASCII_uppercase_a_position = 65; // represents 'A'
        static constexpr int ASCII_uppercase_f_position = 70; // represents 'F'
        const auto uppercase = gen::inRange(ASCII_uppercase_a_position, ASCII_uppercase_f_position + 1);

        static constexpr int ASCII_lowercase_a_position = 97;  // represents 'a'
        static constexpr int ASCII_lowercase_f_position = 102; // represents 'f'
        const auto lowercase = gen::inRange(ASCII_lowercase_a_position, ASCII_lowercase_f_position + 1);

        return gen::map(gen::oneOf(numbers, uppercase, lowercase), [](const auto &c)
                        { return std::string{static_cast<char>(c)}; });
    }

    // Generate invalid hexadecimal characters
    return gen::map(gen::suchThat(asciiPrintableCode(), [](const auto &c)
                                  { return isxdigit(c) == 0; }),
                    [](const auto &c)
                    {
                        return std::string{static_cast<char>(c)};
                    });
}
/**
 * @brief Generates a hextet value of an IPv6 address.
 * @details This function generates a hextet (4 characters) value of an IPv6 address,
 * which may consist of valid or invalid hexadecimal characters based on the \p valid parameter.
 * @param valid A boolean indicating whether the generated hextet should only contain valid hexadecimal characters.
 *              If set to \c true, all characters will be valid. If set to \c false, at least one character will be invalid.
 *              Default is \c true.
 * @return A generator producing either valid or invalid hextet value.
 *
 * Example usage:
 * @code
 * auto hextet = *IPv6HextetValue();
 * @endcode
 */
inline auto IPv6HextetValue(const bool valid = true) -> Gen<std::string>
{
    static constexpr int hexchars_number = 4;
    static constexpr std::array<bool, hexchars_number> all_true = {true, true, true, true};
    const auto hexchar_validity = valid ? all_true : *atLeastOneFalse<hexchars_number>().as("first,second,third,fourth hexchar in hextet valid");

    return gen::map(
        gen::tuple(hexChar(hexchar_validity[0]),
                   hexChar(hexchar_validity[1]),
                   hexChar(hexchar_validity[2]),
                   hexChar(hexchar_validity[3])),
        [](const auto &hexchars)
        {
            const auto &[first_hexchar, second_hexchar, third_hexchar, fourth_hexchar] = hexchars;
            return first_hexchar + second_hexchar + third_hexchar + fourth_hexchar;
        });
}

/**
 * @brief Generates a random IPv6 address.
 * @details This function generates a random IPv6 address. The validity of the hextets
 * can be controlled by the \p valid parameter. If \p valid is \c true, all eight
 * hextets will be valid. Otherwise, at least one hextet will be invalid.
 * The resulting IPv6 address is formatted as \c X:X:X:X:X:X:X:X where \c X is a hextet (4 hex chars)
 * within the valid ranges of \c 0-9, \c A-F, and \c a-f.
 * @details This function generates either a valid or an invalid IPv6 address.
 * @param valid A boolean flag indicating whether the generated IPv6 address should be valid.
 *              Defaults to \c true.
 * @return A generator that produces a valid or invalid IPv6 address.
 *
 * Example usage:
 * @code
 * auto address = *IPv6Address();
 * @endcode
 */
inline auto IPv6Address(const bool valid = true) -> Gen<std::string>
{
    static constexpr int number_of_hextets = 8;
    static constexpr std::array<bool, number_of_hextets> all_true = {true, true, true, true, true, true, true, true};
    const auto hextet_validity = valid ? all_true : *atLeastOneFalse<number_of_hextets>().as("first,second,third,fourth,fifth,sixth,seventh,eighth hextet valid");

    return gen::oneOf(gen::map(
                          gen::tuple(
                              IPv6HextetValue(hextet_validity[0]),
                              IPv6HextetValue(hextet_validity[1]),
                              IPv6HextetValue(hextet_validity[2]),
                              IPv6HextetValue(hextet_validity[3]),
                              IPv6HextetValue(hextet_validity[4]),
                              IPv6HextetValue(hextet_validity[5]),
                              IPv6HextetValue(hextet_validity[6]),
                              IPv6HextetValue(hextet_validity[7])),
                          [](const auto &hextets)
                          {
                              const auto& [first_hextet, second_hextet, third_hextet, fourth_hextet, fifth_hextet, sixth_hextet, seventh_hextet, eighth_hextet] = hextets;
                              return first_hextet + ":" + second_hextet + ":" + third_hextet + ":" + fourth_hextet + ":" + fifth_hextet + ":" +  sixth_hextet + ":" + seventh_hextet + ":" + eighth_hextet; }),
                      gen::just(std::string{"::0"}).as("valid IPv6 address"));
}

using RedirectGatewayFlagsValues = openvpn::RedirectGatewayFlags::Flags;

/**
 * @brief Template specialization for generating arbitrary RedirectGatewayFlagsValues.
 * @details This struct specializes the Arbitrary template for the RedirectGatewayFlagsValues enum.
 * It generates a set of flags by selecting a subset of bit positions to set.
 */
template <>
struct Arbitrary<RedirectGatewayFlagsValues>
{
    /**
     * @brief Generates an arbitrary RedirectGatewayFlagsValues.
     * @details This function generates an arbitrary value for RedirectGatewayFlagsValues
     * by selecting a subset of bit positions (from 0 to number_of_flags) and setting
     * the corresponding bits in the result.
     * @return A generator that produces RedirectGatewayFlagsValues with random sets of flags.
     */
    static Gen<RedirectGatewayFlagsValues> arbitrary()
    {
        static constexpr int number_of_flags = 9;
        return gen::map(
            gen::container<std::vector<int>>(gen::inRange(0, number_of_flags + 1)),
            [](const auto &bit_positions)
            {
                auto flags = static_cast<RedirectGatewayFlagsValues>(0);
                for (const auto &pos : bit_positions)
                {
                    flags = static_cast<RedirectGatewayFlagsValues>(flags | (1 << pos));
                }
                return flags;
            });
    }
};


} // namespace rc
#endif // TEST_GENERATORS_H
