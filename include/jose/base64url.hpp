#ifndef JOSE_BASE64URL_HPP
#define JOSE_BASE64URL_HPP

#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {

/**
 * @brief Base64URL encoding/decoding utilities
 */
class Base64Url
{
public:
    /**
     * @brief Encode data to base64url format
     * @param data Data to encode
     * @return Base64URL encoded string
     */
    static std::string encode(const std::vector<unsigned char>& data);

    /**
     * @brief Encode string to base64url format
     * @param str String to encode
     * @return Base64URL encoded string
     */
    static std::string encode(const std::string& str);

    /**
     * @brief Decode base64url string
     * @param encoded Base64URL encoded string
     * @return Decoded data
     */
    static std::vector<unsigned char> decode(const std::string& encoded);

    /**
     * @brief Decode base64url string to string
     * @param encoded Base64URL encoded string
     * @return Decoded string
     */
    static std::string decodeToString(const std::string& encoded);
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_BASE64URL_HPP
