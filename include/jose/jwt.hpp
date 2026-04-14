#ifndef JOSE_JWT_HPP
#define JOSE_JWT_HPP

#include <chrono>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {

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
    JWT(const JWT &other);
    JWT &operator=(const JWT &other);
    JWT(JWT &&other) noexcept;
    JWT &operator=(JWT &&other) noexcept;

    /**
     * @brief Set issuer claim (iss)
     */
    void setIssuer(std::string const &iss);

    /**
     * @brief Set subject claim (sub)
     */
    void setSubject(std::string const &sub);

    /**
     * @brief Set audience claim (aud)
     */
    void setAudience(std::string const &aud);

    /**
     * @brief Set audience claim with multiple values
     */
    void setAudience(std::vector<std::string> const &aud);

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
    void setJWTID(std::string const &jti);

    /**
     * @brief Set a custom claim
     */
    void setClaim(std::string const &name, std::string const &value);

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
    std::string getJWTID() const;

    /**
     * @brief Get custom claim
     */
    std::string getClaim(std::string const &name) const;

    /**
     * @brief Check if claim exists
     */
    bool hasClaim(std::string const &name) const;

    /**
     * @brief Sign and serialize the JWT
     * @param key Signing key
     * @param algorithm Algorithm to use
     * @return JWT string
     */
    std::string sign(const JWK &key, std::string const &algorithm = "RS256") const;

    /**
     * @brief Verify and parse a JWT
     * @param jwt JWT string
     * @param key Verification key
     * @return JWT object
     */
    static JWT verify(std::string const &jwt, const JWK &key);

    /**
     * @brief Verify and parse a JWT without throwing
     * @param jwt JWT string
     * @param key Verification key
     * @return JWT object, or empty on failure
     */
    static std::optional<JWT>
    verify(std::string const &jwt, JWK const &key, std::nothrow_t const &) noexcept;

    /**
     * @brief Parse a JWT without verification
     * @param jwt JWT string
     * @return JWT object
     */
    static JWT parse(std::string const &jwt);

    /**
     * @brief Parse a JWT without verification and without throwing
     * @param jwt JWT string
     * @return JWT object, or empty on failure
     */
    static std::optional<JWT> parse(std::string const &jwt, std::nothrow_t const &) noexcept;

    /**
     * @brief Validate JWT claims
     * @param issuer Expected issuer (optional)
     * @param audience Expected audience (optional)
     * @param leeway Time leeway in seconds for time-based claims
     * @return true if valid, false otherwise
     */
    bool validate(std::string const &issuer = "",
                  std::string const &audience = "",
                  int leeway = 0) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    static std::pair<std::optional<JWT>, std::string> parse_(std::string const &jwt);
    static std::pair<std::optional<JWT>, std::string> verify_(std::string const &jwt,
                                                              JWK const &key);
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWT_HPP
