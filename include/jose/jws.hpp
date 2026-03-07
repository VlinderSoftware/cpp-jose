#ifndef JOSE_JWS_HPP
#define JOSE_JWS_HPP

#include <memory>
#include <string>

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
    JWS();
    ~JWS();

    // Copy and move constructors/operators
    JWS(const JWS &other);
    JWS &operator=(const JWS &other);
    JWS(JWS &&other) noexcept;
    JWS &operator=(JWS &&other) noexcept;

    /**
     * @brief Set the payload
     * @param payload Payload data
     */
    void setPayload(const std::string &payload);

    /**
     * @brief Set the algorithm
     * @param algorithm Signature algorithm
     */
    void setAlgorithm(JWA::SignatureAlgorithm algorithm);

    /**
     * @brief Set the key ID
     * @param kid Key ID
     */
    void setKeyID(const std::string &kid);

    /**
     * @brief Set the type header
     * @param typ Type (e.g., "JWT")
     */
    void setType(const std::string &typ);

    /**
     * @brief Set a custom header parameter
     * @param name Parameter name
     * @param value Parameter value
     */
    void setHeaderParam(const std::string &name, const std::string &value);

    /**
     * @brief Sign the payload
     * @param key Signing key
     * @return JWS in compact serialization format
     */
    std::string sign(const JWK &key) const;

    /**
     * @brief Verify and parse a JWS
     * @param jws JWS in compact serialization format
     * @param key Verification key
     * @return true if valid, false otherwise
     */
    static bool verify(const std::string &jws, const JWK &key);

    /**
     * @brief Parse a JWS without verification
     * @param jws JWS in compact serialization format
     * @return JWS object
     */
    static JWS parse(const std::string &jws);

    /**
     * @brief Get the payload (after parsing or setting)
     */
    std::string getPayload() const;

    /**
     * @brief Get the header as JSON
     */
    std::string getHeader() const;

    /**
     * @brief Get the algorithm
     */
    JWA::SignatureAlgorithm getAlgorithm() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWS_HPP
