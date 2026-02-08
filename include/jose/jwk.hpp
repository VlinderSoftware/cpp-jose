#ifndef JOSE_JWK_HPP
#define JOSE_JWK_HPP

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Vlinder {
namespace jose {

/**
 * @brief JSON Web Key (RFC 7517)
 *
 * Represents a cryptographic key in JSON format
 */
class JWK
{
public:
    enum class KeyType
    {
        RSA,
        EC,
        OKP,  // Octet Key Pair (for post-quantum)
        oct   // Symmetric key
    };

    enum class Use
    {
        Signature,
        Encryption
    };

    JWK();
    ~JWK();

    // Copy and move constructors/operators
    JWK(const JWK& other);
    JWK& operator=(const JWK& other);
    JWK(JWK&& other) noexcept;
    JWK& operator=(JWK&& other) noexcept;

    /**
     * @brief Parse JWK from JSON string
     * @param json JSON string
     * @return JWK object
     */
    static JWK fromJson(const std::string& json);

    /**
     * @brief Generate a new RSA key
     * @param bits Key size in bits (2048, 3072, 4096)
     * @return JWK object
     */
    static JWK generateRSA(int bits = 2048);

    /**
     * @brief Generate a new EC key
     * @param curve Curve name (P-256, P-384, P-521)
     * @return JWK object
     */
    static JWK generateEC(const std::string& curve = "P-256");

    /**
     * @brief Generate a new symmetric key
     * @param bits Key size in bits
     * @return JWK object
     */
    static JWK generateOct(int bits = 256);

    /**
     * @brief Serialize to JSON
     * @param includePrivate Include private key components
     * @return JSON string
     */
    std::string toJson(bool includePrivate = false) const;

    /**
     * @brief Get key type
     */
    KeyType getKeyType() const;

    /**
     * @brief Set key ID
     */
    void setKeyId(const std::string& kid);

    /**
     * @brief Get key ID
     */
    std::string getKeyId() const;

    /**
     * @brief Set key use
     */
    void setUse(Use use);

    /**
     * @brief Set algorithm
     */
    void setAlgorithm(const std::string& alg);

    /**
     * @brief Get algorithm
     */
    std::string getAlgorithm() const;

    /**
     * @brief Check if key has private components
     */
    bool hasPrivateKey() const;

    /**
     * @brief Get the underlying OpenSSL key
     */
    void* getKey() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief JSON Web Key Set (RFC 7517)
 */
class JWKSet
{
public:
    JWKSet();
    ~JWKSet();

    // Move constructors/operators
    JWKSet(JWKSet&& other) noexcept = default;
    JWKSet& operator=(JWKSet&& other) noexcept = default;

    /**
     * @brief Parse JWK Set from JSON
     */
    static JWKSet fromJson(const std::string& json);

    /**
     * @brief Add a key to the set
     */
    void addKey(const JWK& key);

    /**
     * @brief Get key by ID
     */
    JWK getKey(const std::string& kid) const;

    /**
     * @brief Get all keys
     */
    std::vector<JWK> getKeys() const;

    /**
     * @brief Serialize to JSON
     */
    std::string toJson() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace jose
}  // namespace Vlinder

#endif  // JOSE_JWK_HPP
