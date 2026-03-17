#ifndef JOSE_JWE_HPP
#define JOSE_JWE_HPP

#include <memory>
#include <new>
#include <string>

#include "jwa.hpp"

namespace Vlinder {
namespace JOSE {

class JWK;

/**
 * @brief JSON Web Encryption (RFC 7516)
 *
 * Provides encryption functionality for JOSE
 */
class JWE
{
public:
    JWE();
    ~JWE();

    // Copy and move constructors/operators
    JWE(const JWE &other);
    JWE &operator=(const JWE &other);
    JWE(JWE &&other) noexcept;
    JWE &operator=(JWE &&other) noexcept;

    /**
     * @brief Set the plaintext payload
     * @param plaintext Plaintext data
     */
    void setPlaintext(std::string const &plaintext);

    /**
     * @brief Set the key encryption algorithm
     * @param algorithm Key encryption algorithm
     */
    void setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm algorithm);

    /**
     * @brief Set the content encryption algorithm
     * @param algorithm Content encryption algorithm
     */
    void setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm algorithm);

    /**
     * @brief Set the key ID
     * @param kid Key ID
     */
    void setKeyID(std::string const &kid);

    /**
     * @brief Set the type header
     * @param typ Type
     */
    void setType(std::string const &typ);

    /**
     * @brief Set a custom header parameter
     * @param name Parameter name
     * @param value Parameter value
     */
    void setHeaderParam(std::string const &name, std::string const &value);

    /**
     * @brief Encrypt the payload
     * @param key Encryption key
     * @return JWE in compact serialization format
     */
    std::string encrypt(const JWK &key) const;

    /**
     * @brief Decrypt a JWE
     * @param jwe JWE in compact serialization format
     * @param key Decryption key
     * @return Decrypted plaintext
     */
    static std::string decrypt(std::string const &jwe, const JWK &key);

    /**
     * @brief Parse a JWE without decryption
     * @param jwe JWE in compact serialization format
     * @return JWE object
     */
    static JWE fromJSON(std::string const &jwe);

    /**
     * @brief Parse a JWE without decryption
     * @param jwe JWE in compact serialization format
     * @return JWE object
     */
    static std::pair<std::optional<JWE>, bool> fromJSON(std::string const &jwe,
                                                        std::nothrow_t const &);

    /**
     * @brief Get the plaintext (after parsing or setting)
     */
    std::string getPlaintext() const;

    /**
     * @brief Get the header as JSON
     */
    std::string getHeader() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWE_HPP
