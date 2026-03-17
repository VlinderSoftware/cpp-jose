#ifndef JOSE_JWK_SET_HPP
#define JOSE_JWK_SET_HPP

#include <memory>
#include <string>
#include <vector>

#include "jwk.hpp"

namespace Vlinder {
namespace JOSE {

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
    static JWKSet fromJSON(std::string const &json, bool ignore_private_if_present = false);

    /**
     * @brief Add a key to the set
     */
    void addKey(JWK const &key);

    /**
     * @brief Get key by ID
     */
    JWK getKey(std::string const &kid)
        const;  // TODO return a std::variant<JWK, JWE> where the JWE would contain an encrypted JWK

    /**
     * @brief Get all keys
     */
    std::vector<JWK> getKeys() const;  // TODO the vector should contain a std::variant<JWK, JWE>
                                       // where the JWE would contain an encrypted JWK

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

#endif  // JOSE_JWK_SET_HPP
