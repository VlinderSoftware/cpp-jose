#ifndef JOSE_JWE_HPP
#define JOSE_JWE_HPP

#include <memory>
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
    JWE(const JWE& other);
    JWE& operator=(const JWE& other);
    JWE(JWE&& other) noexcept;
    JWE& operator=(JWE&& other) noexcept;

    /**
     * @brief Set the plaintext payload
     * @param plaintext Plaintext data
     */
    void setPlaintext(const std::string& plaintext);

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
    void setKeyID(const std::string& kid);

    /**
     * @brief Set the type header
     * @param typ Type
     */
    void setType(const std::string& typ);

    /**
     * @brief Set a custom header parameter
     * @param name Parameter name
     * @param value Parameter value
     */
    void setHeaderParam(const std::string& name, const std::string& value);

    /**
     * @brief Encrypt the payload
     * @param key Encryption key
     * @return JWE in compact serialization format
     */
    std::string encrypt(const JWK& key) const;

    /**
     * @brief Decrypt a JWE
     * @param jwe JWE in compact serialization format
     * @param key Decryption key
     * @return Decrypted plaintext
     */
    static std::string decrypt(const std::string& jwe, const JWK& key);

    /**
     * @brief Parse a JWE without decryption
     * @param jwe JWE in compact serialization format
     * @return JWE object
     */
    static JWE parse(const std::string& jwe);

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
