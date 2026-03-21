#ifndef JOSE_JWK_THUMBPRINT_HPP
#define JOSE_JWK_THUMBPRINT_HPP

#include <ostream>
#include <string>
#include <vector>

namespace Vlinder {
namespace JOSE {

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
     * @brief Compute JWK thumbprint using specified hash algorithm
     * @param key JWK to compute thumbprint for
     * @param algorithm Hash algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
     * @return Base64URL-encoded thumbprint
     */
    static JWKThumbprint compute(JWK const &key, std::string const &algorithm = "SHA-256");

    std::string get() const;
    std::vector<unsigned char> getRaw() const
    {
        return value_;
    }

private:
    JWKThumbprint(std::vector<unsigned char> const &value) : value_(value)
    {
    }

    /**
     * @brief Compute raw thumbprint bytes
     * @param key JWK to compute thumbprint for
     * @param algorithm Hash algorithm
     * @return Raw thumbprint bytes
     */
    static std::vector<unsigned char> computeRaw(JWK const &key,
                                                 std::string const &algorithm = "SHA-256");

    std::vector<unsigned char> value_;
};

std::ostream &operator<<(std::ostream &os, JWKThumbprint const &thumbprint);

bool operator==(JWKThumbprint const &lhs, JWKThumbprint const &rhs);
bool operator!=(JWKThumbprint const &lhs, JWKThumbprint const &rhs);
bool operator<(JWKThumbprint const &lhs, JWKThumbprint const &rhs);
bool operator<=(JWKThumbprint const &lhs, JWKThumbprint const &rhs);
bool operator>(JWKThumbprint const &lhs, JWKThumbprint const &rhs);
bool operator>=(JWKThumbprint const &lhs, JWKThumbprint const &rhs);

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWK_THUMBPRINT_HPP
