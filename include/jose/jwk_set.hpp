#ifndef JOSE_JWK_SET_HPP
#define JOSE_JWK_SET_HPP

#include <initializer_list>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "jwe.hpp"
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
    JWKSet(std::initializer_list<std::variant<JWK, JWE>> keys);
    ~JWKSet();

    // Move constructors/operators
    JWKSet(JWKSet &&other) noexcept = default;
    JWKSet &operator=(JWKSet &&other) noexcept = default;

    /**
     * @brief Parse JWK Set from JSON
     */
    static JWKSet fromJSON(std::string const &json, bool ignore_private_if_present = false);

    /**
     * @brief Parse JWK Set from JSON (non-throwing overload)
     * @param json JSON string containing a JWK Set
     * @param ignore_private_if_present Ignore private key material if present
     * @return std::optional<JWKSet> containing the parsed set, or empty on failure
     */
    static std::optional<JWKSet> fromJSON(std::string const &json,
                                          bool ignore_private_if_present,
                                          std::nothrow_t const &) noexcept;

    /**
     * @brief Add a key to the set
     */
    void addKey(std::variant<JWK, JWE> const &key);

    /**
     * @brief Get key by ID
     */
    std::variant<JWK, JWE> getKey(std::string const &kid, std::string const &alg = {}) const;

    /**
     * @brief Get all keys
     */
    std::vector<std::variant<JWK, JWE>> getKeys() const;

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
