#ifndef JOSE_JWS_HPP
#define JOSE_JWS_HPP

#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

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
     * @brief Load JWS from compact or JSON serialization
     * @param input Compact or JSON serialization string
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
     * @brief Try to load JWS from compact or JSON serialization
     * @param input Compact or JSON serialization string
     * @return Pair of optional JWS object and success flag
     */
    static std::pair<std::optional<JWS>, bool> tryLoad(std::string const &input) noexcept;

    /**
     * @brief Try to load JWS from JSON serialization
     * @param json JSON serialization string
     * @param nothrow If true, do not throw exceptions on failure
     * @return Pair of optional JWS object and success flag
     */
    static std::pair<std::optional<JWS>, bool> fromJSON(std::string const &json,
                                                        std::nothrow_t const &) noexcept;

    /**
     * @brief Try to load JWS from compact serialization
     * @param compact Compact serialization string
     * @param nothrow If true, do not throw exceptions on failure
     * @return Pair of optional JWS object and success flag
     */
    static std::pair<std::optional<JWS>, bool> fromCompact(std::string const &compact,
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
 * @param header_params Additional header parameters
 * @param payload Data to sign
 * @return JWS object representing the signed data
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
 * @param header_params Additional header parameters
 * @param payload Data to sign
 * @return JWS object representing the signed data
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
 * @param type Type (e.g., "JWT")
 * @param payload Data to sign
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
 * @param header_params Additional header parameters
 * @param payload Data to sign
 * @return JWS object representing the signed data
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
 * @param header_params Additional header parameters
 * @param payload Data to sign
 * @return JWS object representing the signed data
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

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWS_HPP
