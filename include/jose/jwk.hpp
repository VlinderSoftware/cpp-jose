#ifndef JOSE_JWK_HPP
#define JOSE_JWK_HPP

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {

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
        rsa,
        ec,
        okp,  // Octet Key Pair (RFC 8037: Ed25519/Ed448/X25519/X448)
        oct   // Symmetric key
    };

    enum class Use
    {
        signature,
        encryption
    };

    ~JWK();

    // Copy and move constructors/operators
    JWK(const JWK &other);
    JWK &operator=(const JWK &other);
    JWK(JWK &&other) noexcept;
    JWK &operator=(JWK &&other) noexcept;

    /**
     * @brief Parse JWK from JSON string
     * @param json JSON string
     * @return JWK object
     */
    static JWK fromJSON(const std::string &json, bool permissive = false);

    /**
     * @brief Generate a new RSA key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param bits Key size in bits (2048, 3072, 4096)
     * @param alg Optional algorithm. If empty, defaults to RS256 (sig) or RSA-OAEP-256 (enc)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateRSA(Use use, unsigned int bits = 2048, const std::string &alg = {});

    /**
     * @brief Generate a new EC key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param curve Curve name (P-256, P-384, P-521)
     * @param alg Optional algorithm. If empty, defaults based on curve (ES256/ES384/ES512)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateEC(Use use, const std::string &curve = "P-256", const std::string &alg = "");

    /**
     * @brief Generate a new symmetric key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param bits Key size in bits
     * @param alg Optional algorithm. If empty, defaults to HS256 (sig) or A256KW (enc)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateOct(Use use, int bits = 256, const std::string &alg = "");
    static JWK generateOKP(Use use,
                           unsigned int bits = 0 /*default depends on use*/,
                           const std::string &alg = {});

    /**
     * @brief Serialize to JSON
     * @param include_private Include private key components
     * @return JSON string
     */
    std::string toJSON(bool include_private = false) const;

    /**
     * @brief Get key type
     */
    KeyType getKeyType() const;

    /**
     * @brief Set key ID
     */
    void setKeyID(const std::string &kid);

    /**
     * @brief Get key ID
     */
    std::string getKeyID() const;

    /**
     * @brief Set key use
     */
    void setUse(Use use);

    /**
     * @brief Set algorithm
     */
    void setAlgorithm(const std::string &alg);

    /**
     * @brief Get algorithm
     */
    std::string getAlgorithm() const;

    /**
     * @brief Check if key has private components
     */
    bool hasPrivateKey() const;

private:
    struct Impl;

    JWK(Impl &&impl);

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
    JWKSet(JWKSet &&other) noexcept = default;
    JWKSet &operator=(JWKSet &&other) noexcept = default;

    /**
     * @brief Parse JWK Set from JSON
     */
    static JWKSet fromJSON(const std::string &json);

    /**
     * @brief Add a key to the set
     */
    void addKey(const JWK &key);

    /**
     * @brief Get key by ID
     */
    JWK getKey(const std::string &kid) const;

    /**
     * @brief Get all keys
     */
    std::vector<JWK> getKeys() const;

    /**
     * @brief Serialize to JSON
     */
    std::string toJSON() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWK_HPP
