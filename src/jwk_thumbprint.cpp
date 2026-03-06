#include "jwk_thumbprint.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <stdexcept>

#include "base64url.hpp"
#include "private/json_utils.hpp"
#include "jwk.hpp"
#include "private/back_end_factory.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

namespace {

Private::BackEnd &getBackEnd()
{
    static std::once_flag flag;
    static std::unique_ptr< Private::BackEnd > back_end;
    std::call_once(flag,
                   [&]()
                   {
                       back_end = std::move(Private::BackEndFactory::get().createBackEnd());
                   });
    return *back_end;
}

// Extract required JWK components in lexicographic order per RFC 7638
std::string getCanonicalJWKJson(JWK const &key)
{
    // For symmetric (oct) keys, we need to include the private key material
    // For asymmetric keys, we only need the public key
    bool const include_private = (key.getKeyType() == JWK::KeyType::oct);
    std::string const full_json = key.toJSON(include_private);
    json const jwk_value = json::parse(full_json);

    if (!jwk_value.contains("kty"))
    {
        throw std::runtime_error("JWK missing required 'kty' field");
    }

    std::string const kty = jwk_value["kty"].get<std::string>();
    json canonical = json::object();

    if (kty == "RSA")
    {
        if (!jwk_value.contains("e") || !jwk_value.contains("n"))
        {
            throw std::runtime_error("RSA JWK missing required fields");
        }
        std::string const e = jwk_value["e"].get<std::string>();
        std::string const n = jwk_value["n"].get<std::string>();
        return "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
    }
    else if (kty == "EC")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x") || !jwk_value.contains("y"))
        {
            throw std::runtime_error("EC JWK missing required fields");
        }
        std::string const crv = jwk_value["crv"].get<std::string>();
        std::string const x = jwk_value["x"].get<std::string>();
        std::string const y = jwk_value["y"].get<std::string>();
        return "{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
    }
    else if (kty == "oct")
    {
        if (!jwk_value.contains("k"))
        {
            throw std::runtime_error("oct JWK missing required 'k' field");
        }
        std::string const k = jwk_value["k"].get<std::string>();
        return "{\"k\":\"" + k + "\",\"kty\":\"oct\"}";
    }
    else if (kty == "OKP")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x"))
        {
            throw std::runtime_error("OKP JWK missing required fields");
        }
        std::string const crv = jwk_value["crv"].get<std::string>();
        std::string const x = jwk_value["x"].get<std::string>();
        return "{\"crv\":\"" + crv + "\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}";
    }
    else
    {
        throw std::runtime_error("Unsupported key type: " + kty);
    }
}

Private::HashAlgorithm getHashAlgorithm(std::string const &algorithm)
{
    if (algorithm == "SHA-256")
    {
        return Private::HashAlgorithm::sha256;
    }
    else if (algorithm == "SHA-384")
    {
        return Private::HashAlgorithm::sha384;
    }
    else if (algorithm == "SHA-512")
    {
        return Private::HashAlgorithm::sha512;
    }
    else
    {
        throw std::runtime_error("Unsupported hash algorithm: " + algorithm);
    }
}

}  // anonymous namespace

std::string JWKThumbprint::compute(JWK const &key)
{
    return compute(key, "SHA-256");
}

std::string JWKThumbprint::compute(JWK const &key, std::string const &algorithm)
{
    std::vector<unsigned char> const raw_thumbprint = computeRaw(key, algorithm);
    return Base64Url::encode(raw_thumbprint);
}

std::vector<unsigned char> JWKThumbprint::computeRaw(JWK const &key, std::string const &algorithm)
{
    std::string const canonical_json = getCanonicalJWKJson(key);
    auto const hash_algorithm = getHashAlgorithm(algorithm);
    std::vector<unsigned char> const input(canonical_json.begin(), canonical_json.end());
    auto const &back_end = getBackEnd();
    return back_end.hash(hash_algorithm, input);
}

}  // namespace JOSE
}  // namespace Vlinder
