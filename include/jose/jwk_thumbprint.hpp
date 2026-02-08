#ifndef JOSE_JWK_THUMBPRINT_HPP
#define JOSE_JWK_THUMBPRINT_HPP

#include <string>
#include <vector>

namespace Vlinder
{
namespace jose
{

class JWK;

/**
 * @brief JSON Web Key Thumbprint (RFC 7638)
 * 
 * Computes thumbprints of JWKs
 */
class JWKThumbprint
{
public:
    /**
     * @brief Compute JWK thumbprint using SHA-256
     * @param key JWK to compute thumbprint for
     * @return Base64URL-encoded thumbprint
     */
    static std::string compute(const JWK& key);
    
    /**
     * @brief Compute JWK thumbprint using specified hash algorithm
     * @param key JWK to compute thumbprint for
     * @param algorithm Hash algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
     * @return Base64URL-encoded thumbprint
     */
    static std::string compute(const JWK& key, const std::string& algorithm);
    
    /**
     * @brief Compute raw thumbprint bytes
     * @param key JWK to compute thumbprint for
     * @param algorithm Hash algorithm
     * @return Raw thumbprint bytes
     */
    static std::vector<unsigned char> computeRaw(const JWK& key, const std::string& algorithm = "SHA-256");
};

} // namespace jose
} // namespace Vlinder

#endif // JOSE_JWK_THUMBPRINT_HPP
