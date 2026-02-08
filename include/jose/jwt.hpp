#ifndef JOSE_JWT_HPP
#define JOSE_JWT_HPP

#include <string>
#include <memory>
#include <vector>
#include <chrono>

namespace Vlinder
{
namespace jose
{

class JWK;

/**
 * @brief JSON Web Token (RFC 7519)
 * 
 * Provides claims-based token functionality
 */
class JWT
{
public:
    JWT();
    ~JWT();
    
    // Copy and move constructors/operators
    JWT(const JWT& other);
    JWT& operator=(const JWT& other);
    JWT(JWT&& other) noexcept;
    JWT& operator=(JWT&& other) noexcept;
    
    /**
     * @brief Set issuer claim (iss)
     */
    void setIssuer(const std::string& iss);
    
    /**
     * @brief Set subject claim (sub)
     */
    void setSubject(const std::string& sub);
    
    /**
     * @brief Set audience claim (aud)
     */
    void setAudience(const std::string& aud);
    
    /**
     * @brief Set audience claim with multiple values
     */
    void setAudience(const std::vector<std::string>& aud);
    
    /**
     * @brief Set expiration time claim (exp)
     */
    void setExpiration(std::chrono::system_clock::time_point exp);
    
    /**
     * @brief Set not before claim (nbf)
     */
    void setNotBefore(std::chrono::system_clock::time_point nbf);
    
    /**
     * @brief Set issued at claim (iat)
     */
    void setIssuedAt(std::chrono::system_clock::time_point iat);
    
    /**
     * @brief Set JWT ID claim (jti)
     */
    void setJwtId(const std::string& jti);
    
    /**
     * @brief Set a custom claim
     */
    void setClaim(const std::string& name, const std::string& value);
    
    /**
     * @brief Get issuer claim
     */
    std::string getIssuer() const;
    
    /**
     * @brief Get subject claim
     */
    std::string getSubject() const;
    
    /**
     * @brief Get audience claim
     */
    std::vector<std::string> getAudience() const;
    
    /**
     * @brief Get expiration time
     */
    std::chrono::system_clock::time_point getExpiration() const;
    
    /**
     * @brief Get not before time
     */
    std::chrono::system_clock::time_point getNotBefore() const;
    
    /**
     * @brief Get issued at time
     */
    std::chrono::system_clock::time_point getIssuedAt() const;
    
    /**
     * @brief Get JWT ID
     */
    std::string getJwtId() const;
    
    /**
     * @brief Get custom claim
     */
    std::string getClaim(const std::string& name) const;
    
    /**
     * @brief Check if claim exists
     */
    bool hasClaim(const std::string& name) const;
    
    /**
     * @brief Sign and serialize the JWT
     * @param key Signing key
     * @param algorithm Algorithm to use
     * @return JWT string
     */
    std::string sign(const JWK& key, const std::string& algorithm = "RS256") const;
    
    /**
     * @brief Verify and parse a JWT
     * @param jwt JWT string
     * @param key Verification key
     * @return JWT object
     */
    static JWT verify(const std::string& jwt, const JWK& key);
    
    /**
     * @brief Parse a JWT without verification
     * @param jwt JWT string
     * @return JWT object
     */
    static JWT parse(const std::string& jwt);
    
    /**
     * @brief Validate JWT claims
     * @param issuer Expected issuer (optional)
     * @param audience Expected audience (optional)
     * @param leeway Time leeway in seconds for time-based claims
     * @return true if valid, false otherwise
     */
    bool validate(
        const std::string& issuer = "",
        const std::string& audience = "",
        int leeway = 0
    ) const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace jose
} // namespace Vlinder

#endif // JOSE_JWT_HPP
