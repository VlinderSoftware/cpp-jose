#ifndef JOSE_JWK_HPP
#define JOSE_JWK_HPP

#include <map>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {
namespace Private {
class BackEnd;
}
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
    static JWK fromJSON(std::string const &json, bool ignore_private_if_present = false);

    /**
     * @brief Parse JWK from JSON string (non-throwing overload)
     * @param json JSON string
     * @param ignore_private_if_present Ignore private key material if present
     * @return std::optional<JWK> containing the parsed key, or empty on failure
     */
    static std::optional<JWK> fromJSON(std::string const &json,
                                       bool ignore_private_if_present,
                                       std::nothrow_t const &) noexcept;

    /**
     * @brief Generate a new RSA key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param bits Key size in bits (2048, 3072, 4096)
     * @param alg Optional algorithm. If empty, defaults to RS256 (sig) or RSA-OAEP-256 (enc)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateRSA(Use use, unsigned int bits = 2048, std::string const &alg = {});

    /**
     * @brief Generate a new EC key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param curve Curve name (P-256, P-384, P-521)
     * @param alg Optional algorithm. If empty, defaults based on curve (ES256/ES384/ES512)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateEC(Use use, std::string const &curve = "P-256", std::string const &alg = "");

    /**
     * @brief Generate a new symmetric key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param bits Key size in bits
     * @param alg Optional algorithm. If empty, defaults to HS256 (sig) or A256KW (enc)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateOct(Use use, int bits = 256, std::string const &alg = "");

    /**
     * @brief Generate a new OKP key
     * @param use Key use (signature or encryption) - REQUIRED
     * @param bits Key size in bits (ignored for OKP, but can be used to specify curve)
     * @param alg Optional algorithm. If empty, defaults based on use (Ed25519 for sig, X25519 for
     * enc)
     * @return JWK object with auto-generated SHA-512 thumbprint as kid
     */
    static JWK generateOKP(Use use,
                           unsigned int bits = 0 /*default depends on use*/,
                           std::string const &alg = {});

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
    void setKeyID(std::string const &kid);

    /**
     * @brief Get key ID
     */
    std::string getKeyID() const;

    /**
     * @brief Check if key use is set
     */
    bool hasUse() const;

    /**
     * @brief Get key use
     */
    Use getUse() const;

    /**
     * @brief Set key use
     */
    void setUse(Use use);

    /**
     * @brief Set algorithm
     */
    void setAlgorithm(std::string const &alg);

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

    static std::pair<std::optional<JWK>, std::string> fromJSON_(std::string const &json,
                                                                bool ignore_private_if_present);

    friend class Private::BackEnd;
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWK_HPP
