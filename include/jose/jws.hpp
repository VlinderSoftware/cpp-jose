#ifndef JOSE_JWS_HPP
#define JOSE_JWS_HPP

#include <iosfwd>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "base64url.hpp"
#include "jwa.hpp"

namespace Vlinder {
namespace JOSE {

class JWK;

/**
 * @brief JSON Web Signature (RFC 7515)
 *
 * Provides digital signature and MAC functionality
 */
class JWS
{
public:
    ~JWS();

    // Copy and move constructors/operators
    JWS(const JWS &other);
    JWS &operator=(const JWS &other);
    JWS(JWS &&other) noexcept;
    JWS &operator=(JWS &&other) noexcept;
    JWS &swap(JWS &other) noexcept;

    /**
     * @brief Load JWS from compact (three-part dot-delimited) serialization
     * @param compact Compact serialization string
     * @return JWS object
     */
    static JWS fromCompact(std::string const &compact);

    /**
     * @brief Load JWS from JSON serialization
     * @param json JSON serialization string
     * @return JWS object
     */
    static JWS fromJSON(std::string const &json);

    /**
     * @brief Try to load JWS from compact or JSON serialization without throwing
     * @param input Compact or JSON serialization string
     * @return `std::optional<JWS>` containing the loaded token if valid, or
     *         empty if the input could not be parsed.
     */
    static std::optional<JWS> tryLoad(std::string const &input) noexcept;

    /**
     * @brief Try to load JWS from JSON serialization without throwing
     * @param json JSON serialization string
     * @return `std::optional<JWS>` containing the loaded token if valid, or
     *         empty if the input could not be parsed.
     */
    static std::optional<JWS> fromJSON(std::string const &json, std::nothrow_t const &) noexcept;

    /**
     * @brief Try to load JWS from compact serialization without throwing
     * @param compact Compact serialization string
     * @return `std::optional<JWS>` containing the loaded token if valid, or
     *         empty if the input could not be parsed.
     */
    static std::optional<JWS> fromCompact(std::string const &compact,
                                          std::nothrow_t const &) noexcept;

    /**
     * @brief Serialize to compact format (three base64url-encoded parts separated by dots)
     * @return Compact serialization string
     */
    std::string toCompact() const;

    /**
     * @brief Serialize to JSON format (general or flattened)
     * @param flattened If true, use flattened JSON serialization
     * @return JSON serialization string
     */
    std::string toJSON(bool flattened = false) const;

    /**
     * @brief Get the payload as a byte vector
     * @return Payload bytes
     */
    std::vector<unsigned char> getPayload() const;

    /**
     * @brief Get the payload as T.
     *
     * Supported specialisations:
     *   - `std::string` -- returns the payload bytes as a UTF-8 string.
     *   - `std::string` with `base64url_encode = true` -- returns the payload
     *     as a base64url-encoded string (no padding).
     *   - `std::vector<unsigned char>` -- identical to the non-template overload.
     *
     * @tparam T  `std::string` or `std::vector<unsigned char>`.
     * @param base64url_encode  When `T` is `std::string`, encode the bytes as
     *                          base64url instead of treating them as raw text.
     *                          Ignored when `T` is `std::vector<unsigned char>`.
     * @return Payload as `T`.
     */
    template <typename T>
    T getPayload(bool base64url_encode = false) const;

private:
    struct Impl;

    JWS(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;

    friend class SignAttorney;  ///< Attorney has full JWS access; it limits what it exposes
                                ///< downstream.
    friend bool verify(JWS const &jws, JWK const &key);
};

/// @brief Attorney that gates the private JWS constructor: only the canonical
///        sign() overload is granted access via friendship with SignAttorney.
class SignAttorney
{
    SignAttorney() = delete;

    /// Constructs a JWS from pre-computed RFC 7515 components on behalf of sign().
    static JWS construct(std::vector<unsigned char> payload,
                         JWA::SignatureAlgorithm alg,
                         std::string kid,
                         std::string typ,
                         std::map<std::string, std::string> header_params,
                         std::string header_b64,
                         std::string payload_b64,
                         std::vector<unsigned char> signature);

    friend JWS sign(JWK const &key,
                    JWA::SignatureAlgorithm alg,
                    std::string const &type,
                    std::map<std::string, std::string> const &header_params,
                    std::span<unsigned char const> const &payload);
};

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::span<unsigned char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::span<char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::span<unsigned char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::span<char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param header_params Additional header parameters to include in the protected header.
 *        Must not contain any reserved JOSE header name: \"alg\", \"kid\", \"typ\",
 *        \"cty\", \"enc\", \"zip\", \"jku\", \"jwk\", \"x5u\", \"x5c\", \"x5t\",
 *        \"x5t#S256\", or \"crit\".
 * @param payload Data to sign
 * @return JWS object representing the signed data
 * @throws std::invalid_argument if any key in \p header_params is a reserved JOSE header name
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::span<unsigned char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param header_params Additional header parameters to include in the protected header.
 *        Must not contain any reserved JOSE header name: \"alg\", \"kid\", \"typ\",
 *        \"cty\", \"enc\", \"zip\", \"jku\", \"jwk\", \"x5u\", \"x5c\", \"x5t\",
 *        \"x5t#S256\", or \"crit\".
 * @param payload Data to sign
 * @return JWS object representing the signed data
 * @throws std::invalid_argument if any key in \p header_params is a reserved JOSE header name
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::span<char const> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::vector<unsigned char> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param payload Data to sign (interpreted as raw bytes)
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::string const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::vector<unsigned char> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param payload Data to sign
 * @return JWS object representing the signed data
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::string const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param header_params Additional header parameters to include in the protected header.
 *        Must not contain any reserved JOSE header name: \"alg\", \"kid\", \"typ\",
 *        \"cty\", \"enc\", \"zip\", \"jku\", \"jwk\", \"x5u\", \"x5c\", \"x5t\",
 *        \"x5t#S256\", or \"crit\".
 * @param payload Data to sign
 * @return JWS object representing the signed data
 * @throws std::invalid_argument if any key in \p header_params is a reserved JOSE header name
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::vector<unsigned char> const &payload);

/**
 * @brief Sign payload with the specified key and algorithm
 * @param key Key to use for signing
 * @param alg Signature algorithm
 * @param type Type (e.g., "JWT")
 * @param header_params Additional header parameters to include in the protected header.
 *        Must not contain any reserved JOSE header name: \"alg\", \"kid\", \"typ\",
 *        \"cty\", \"enc\", \"zip\", \"jku\", \"jwk\", \"x5u\", \"x5c\", \"x5t\",
 *        \"x5t#S256\", or \"crit\".
 * @param payload Data to sign
 * @return JWS object representing the signed data
 * @throws std::invalid_argument if any key in \p header_params is a reserved JOSE header name
 */
JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::string const &payload);

/**
 * @brief Verify JWS signature
 * @param jws JWS object to verify
 * @param key Key to use for verification
 * @return true if signature is valid, false otherwise
 */
bool verify(JWS const &jws, JWK const &key);

std::ostream &operator<<(std::ostream &os, JWS const &jws);
bool operator==(JWS const &lhs, JWS const &rhs);
bool operator!=(JWS const &lhs, JWS const &rhs);
bool operator<(JWS const &lhs, JWS const &rhs);
bool operator<=(JWS const &lhs, JWS const &rhs);
bool operator>(JWS const &lhs, JWS const &rhs);
bool operator>=(JWS const &lhs, JWS const &rhs);

// --- getPayload<T> template definition

template <typename T>
inline T JWS::getPayload(bool base64url_encode) const
{
    if constexpr (std::is_same_v<T, std::string>)
    {
        if (base64url_encode)
            return Base64URL::encode(getPayload());
        auto const bytes = getPayload();
        return std::string(bytes.begin(), bytes.end());
    }
    else
    {
        static_assert(std::is_same_v<T, std::vector<unsigned char>>,
                      "getPayload<T>: T must be std::string or std::vector< unsigned char >");
        return getPayload();
    }
}

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWS_HPP
