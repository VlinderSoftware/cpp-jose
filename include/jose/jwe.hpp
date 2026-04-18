#pragma once

#include <map>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "jwa.hpp"

namespace Vlinder {
namespace JOSE {

class JWK;

/// @brief JSON Web Encryption token (RFC 7516).
///
/// A JWE is created by the free-function @c encrypt() overload family and
/// can be serialised with @c toCompact() or @c toJSON().  It can be
/// deserialised (without decryption) by @c fromCompact() / @c fromJSON().
/// Actual decryption is performed by the free-function @c decrypt() family.
///
/// The public parsing API provides both throwing and nothrow overloads:
/// @c fromCompact() / @c fromJSON() throw @c std::runtime_error on failure,
/// while their nothrow overloads return an empty @c std::optional<JWE>.
/// Public @c decrypt() overloads are throwing-only.
class JWE
{
public:
    ~JWE();

    JWE(JWE const &other);
    JWE &operator=(JWE const &other);
    JWE(JWE &&other) noexcept;
    JWE &operator=(JWE &&other) noexcept;

    // ── Deserialisation ─────────────────────────────────────────────────────

    /// @brief Parse a JWE compact serialisation (five dot-delimited parts, RFC 7516 §7.1)
    ///        without decrypting the content.
    /// @param compact Base64url-encoded compact JWE token.
    /// @return JWE object holding the encoded parts.
    /// @throws std::runtime_error if the input is not a valid compact JWE.
    static JWE fromCompact(std::string const &compact);

    /// @brief Non-throwing variant of @c fromCompact.
    /// @param compact Base64url-encoded compact JWE token.
    /// @return @c std::optional<JWE> holding the parsed token, or empty on failure.
    static std::optional<JWE> fromCompact(std::string const &compact,
                                          std::nothrow_t const &) noexcept;

    /// @brief Parse a JWE full JSON serialisation (RFC 7516 §7.2) without
    ///        decrypting the content.
    /// @param json_str JSON string in the RFC 7516 §7.2 general or flattened format.
    /// @return JWE object holding the encoded parts.
    /// @throws std::runtime_error if the input is not a valid JSON JWE.
    static JWE fromJSON(std::string const &json_str);

    /// @brief Non-throwing variant of @c fromJSON.
    /// @param json_str JSON string in the RFC 7516 §7.2 general or flattened format.
    /// @return @c std::optional<JWE> containing the parsed token, or empty on failure.
    static std::optional<JWE> fromJSON(std::string const &json_str,
                                       std::nothrow_t const &) noexcept;

    // ── Serialisation ────────────────────────────────────────────────────────

    /// @brief Serialise to JWE JSON form (RFC 7516 §7.2), emitting flattened
    ///        serialisation only when there is a single recipient and no
    ///        separate per-recipient header needs to be represented; otherwise
    ///        emits general serialisation.
    /// @return JSON string.
    std::string toJSON() const;

    // ── Observers ────────────────────────────────────────────────────────────

    /// @brief Return the key encryption algorithm parsed from the protected header.
    JWA::KeyEncryptionAlgorithm getKeyEncryptionAlgorithm() const;

    /// @brief Return the content encryption algorithm parsed from the protected header.
    JWA::ContentEncryptionAlgorithm getContentEncryptionAlgorithm() const;

    /// @brief Return the key ID from the protected header, or empty string if absent.
    std::string getKeyID() const;

    /// @brief Return the type field from the protected header, or empty string if absent.
    std::string getType() const;

    /// @brief Return the protected header as a JSON string.
    std::string getHeader() const;

private:
    struct Impl;

    explicit JWE(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;

    static std::pair<std::optional<JWE>, std::string> fromCompact_(std::string const &compact);
    static std::pair<std::optional<JWE>, std::string> fromJSON_(std::string const &json_str);

    friend class EncryptAttorney;
    friend std::vector<unsigned char> decrypt(JWE const &jwe, JWK const &key);
};

/// @brief Attorney that gates the private JWE constructor so that only the
///        canonical @c encrypt() overload is granted construction access.
class EncryptAttorney
{
    EncryptAttorney() = delete;

    /// @brief Construct a JWE from pre-computed RFC 7516 components.
    /// @param kea           Key encryption algorithm.
    /// @param cea           Content encryption algorithm.
    /// @param kid           Key ID (may be empty).
    /// @param typ           Type header field (may be empty).
    /// @param header_params Additional non-reserved header parameters.
    /// @param header_b64    Base64url-encoded protected header.
    /// @param encrypted_key Encrypted content encryption key bytes.
    /// @param iv            Initialisation vector bytes.
    /// @param ciphertext    Ciphertext bytes.
    /// @param auth_tag      Authentication tag bytes.
    /// @return Constructed JWE.
    static JWE construct(JWA::KeyEncryptionAlgorithm kea,
                         JWA::ContentEncryptionAlgorithm cea,
                         std::string kid,
                         std::string typ,
                         std::map<std::string, std::string> header_params,
                         std::string header_b64,
                         std::vector<unsigned char> encrypted_key,
                         std::vector<unsigned char> iv,
                         std::vector<unsigned char> ciphertext,
                         std::vector<unsigned char> auth_tag);

    friend JWE encrypt(JWK const &key,
                       JWA::KeyEncryptionAlgorithm kea,
                       JWA::ContentEncryptionAlgorithm cea,
                       std::string const &type,
                       std::map<std::string, std::string> const &header_params,
                       std::span<unsigned char const> const &payload);
};

// ── encrypt() free-function family ──────────────────────────────────────────

/// @brief Encrypt a payload and return a JWE (RFC 7516).
/// @param key     Recipient key.
/// @param kea     Key encryption algorithm.
/// @param cea     Content encryption algorithm.
/// @param payload Plaintext to encrypt.
/// @return JWE object; call @c toCompact() or @c toJSON() to serialise.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::span<unsigned char const> const &payload);

/// @brief Encrypt a payload with a given type header.
/// @param key     Recipient key.
/// @param kea     Key encryption algorithm.
/// @param cea     Content encryption algorithm.
/// @param type    Value for the @c typ protected header field.
/// @param payload Plaintext to encrypt.
/// @return JWE object.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::string const &type,
            std::span<unsigned char const> const &payload);

/// @brief Encrypt a string payload with a given type header.
/// @param key     Recipient key.
/// @param kea     Key encryption algorithm.
/// @param cea     Content encryption algorithm.
/// @param type    Value for the @c typ protected header field.
/// @param payload Plaintext string.
/// @return JWE object.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::string const &type,
            std::string const &payload);

/// @brief Encrypt a payload with a type header and additional header parameters.
/// @param key           Recipient key.
/// @param kea           Key encryption algorithm.
/// @param cea           Content encryption algorithm.
/// @param type          Value for the @c typ protected header field.
/// @param header_params Additional, non-reserved header parameters.
///                      Must not contain any of the reserved JWE header names:
///                      \"alg\", \"enc\", \"zip\", \"jku\", \"jwk\", \"kid\",
///                      \"x5u\", \"x5c\", \"x5t\", \"x5t#S256\", \"typ\",
///                      \"cty\", \"crit\", \"epk\", \"apu\", \"apv\",
///                      \"iv\", \"tag\", \"p2s\", or \"p2c\".
/// @param payload       Plaintext to encrypt.
/// @return JWE object.
/// @throws std::invalid_argument if any key in @p header_params is a reserved JWE header name.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::string const &type,
            std::map<std::string, std::string> const &header_params,
            std::span<unsigned char const> const &payload);

/// @brief Encrypt a string payload with a type header and additional header parameters.
/// @param key           Recipient key.
/// @param kea           Key encryption algorithm.
/// @param cea           Content encryption algorithm.
/// @param type          Value for the @c typ protected header field.
/// @param header_params Additional, non-reserved header parameters.
///                      Must not contain any of the reserved JWE header names.
/// @param payload       Plaintext string.
/// @return JWE object.
/// @throws std::invalid_argument if any key in @p header_params is a reserved JWE header name.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::string const &type,
            std::map<std::string, std::string> const &header_params,
            std::string const &payload);

/// @brief Encrypt a @c vector<unsigned char> payload.  Convenience overload.
/// @param key     Recipient key.
/// @param kea     Key encryption algorithm.
/// @param cea     Content encryption algorithm.
/// @param payload Plaintext bytes.
/// @return JWE object.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::vector<unsigned char> const &payload);

/// @brief Encrypt a string payload.  Convenience overload.
/// @param key     Recipient key.
/// @param kea     Key encryption algorithm.
/// @param cea     Content encryption algorithm.
/// @param payload Plaintext string.
/// @return JWE object.
/// @throws std::runtime_error on encryption failure.
JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            std::string const &payload);

// ── decrypt() free-function family ──────────────────────────────────────────

/// @brief Decrypt a JWE and return the plaintext bytes.
/// @param jwe JWE object (produced by @c encrypt() or @c fromCompact()).
/// @param key Recipient private key.
/// @return Decrypted plaintext bytes.
/// @throws std::runtime_error on decryption failure.
std::vector<unsigned char> decrypt(JWE const &jwe, JWK const &key);

/// @brief Decrypt a compact JWE token.  Convenience overload; parses the
///        compact form then decrypts.
/// @param compact Compact JWE token string.
/// @param key     Recipient private key.
/// @return Decrypted plaintext bytes.
/// @throws std::runtime_error on parse or decryption failure.
std::vector<unsigned char> decrypt(std::string const &compact, JWK const &key);

}  // namespace JOSE
}  // namespace Vlinder
