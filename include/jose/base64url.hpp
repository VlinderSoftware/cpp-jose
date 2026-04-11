#ifndef JOSE_BASE64URL_HPP
#define JOSE_BASE64URL_HPP

#include <new>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {

/**
 * @brief Base64URL encoding/decoding utilities
 */
class Base64URL
{
public:
    /**
     * @brief Encode data to base64url format
     * @param data Data to encode
     * @return Base64URL encoded string
     */
    static std::string encode(std::span<unsigned char const> const &data);

    /**
     * @brief Encode data to base64url format
     * @param data Data to encode
     * @return Base64URL encoded string
     */
    static std::string encode(std::vector<unsigned char> const &data);

    /**
     * @brief Encode string to base64url format
     * @param str String to encode
     * @return Base64URL encoded string
     */
    static std::string encode(std::string const &str);

    /**
     * @brief Decode base64url string
     * @param encoded Base64URL encoded string
     * @return Decoded data
     */
    static std::vector<unsigned char> decode(std::string const &encoded);

    /**
     * @brief Decode base64url string without throwing
     * @param encoded Base64URL encoded string
     * @return Decoded data, or empty optional on failure
     */
    static std::optional<std::vector<unsigned char>>
    decode(std::string const &encoded, std::nothrow_t const &) noexcept;

    /**
     * @brief Decode base64url string to string
     * @param encoded Base64URL encoded string
     * @return Decoded string
     */
    static std::string decodeToString(std::string const &encoded);

    /**
     * @brief Decode base64url string to string without throwing
     * @param encoded Base64URL encoded string
     * @return Decoded string, or empty optional on failure
     */
    static std::optional<std::string>
    decodeToString(std::string const &encoded, std::nothrow_t const &) noexcept;
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_BASE64URL_HPP
