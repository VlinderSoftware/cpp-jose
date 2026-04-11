#include "jwk_thumbprint.hpp"

#include <algorithm>
#include <map>
#include <mutex>
#include <stdexcept>

#include "base64url.hpp"
#include "jwk.hpp"
#include "private/back_end_factory.hpp"
#include "private/json_utils.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

namespace {

Private::BackEnd &getBackEnd()
{
    static once_flag flag;
    static unique_ptr<Private::BackEnd> back_end;
    call_once(flag,
              [&]()
              {
                  back_end = std::move(Private::BackEndFactory::get().createBackEnd());
              });
    return *back_end;
}

// Extract required JWK components in lexicographic order per RFC 7638
string getCanonicalJWKJson(JWK const &key)
{
    // For symmetric (oct) keys, we need to include the private key material
    // For asymmetric keys, we only need the public key
    bool const include_private = (key.getKeyType() == JWK::KeyType::oct);
    string const full_json = key.toJSON(include_private);
    json const jwk_value = json::parse(full_json);

    if (!jwk_value.contains("kty"))
    {
        throw runtime_error("JWK missing required 'kty' field");
    }

    string const kty = jwk_value["kty"].get<string>();
    json canonical = json::object();

    if (kty == "RSA")
    {
        if (!jwk_value.contains("e") || !jwk_value.contains("n"))
        {
            throw runtime_error("RSA JWK missing required fields");
        }
        string const e = jwk_value["e"].get<string>();
        string const n = jwk_value["n"].get<string>();
        return "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
    }
    else if (kty == "EC")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x") || !jwk_value.contains("y"))
        {
            throw runtime_error("EC JWK missing required fields");
        }
        string const crv = jwk_value["crv"].get<string>();
        string const x = jwk_value["x"].get<string>();
        string const y = jwk_value["y"].get<string>();
        return "{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
    }
    else if (kty == "oct")
    {
        if (!jwk_value.contains("k"))
        {
            throw runtime_error("oct JWK missing required 'k' field");
        }
        string const k = jwk_value["k"].get<string>();
        return "{\"k\":\"" + k + "\",\"kty\":\"oct\"}";
    }
    else if (kty == "OKP")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x"))
        {
            throw runtime_error("OKP JWK missing required fields");
        }
        string const crv = jwk_value["crv"].get<string>();
        string const x = jwk_value["x"].get<string>();
        return "{\"crv\":\"" + crv + "\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}";
    }
    else
    {
        throw runtime_error("Unsupported key type: " + kty);
    }
}

Private::HashAlgorithm getHashAlgorithm(string const &algorithm)
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
        throw runtime_error("Unsupported hash algorithm: " + algorithm);
    }
}

}  // anonymous namespace

JWKThumbprint JWKThumbprint::compute(JWK const &key, string const &algorithm)
{
    return JWKThumbprint(computeRaw(key, algorithm));
}

optional<JWKThumbprint>
JWKThumbprint::compute(JWK const &key, string const &algorithm, nothrow_t const &) noexcept
{
    try
    {
        return make_optional<JWKThumbprint>(compute(key, algorithm));
    }
    catch (...)
    {
        return nullopt;
    }
}

string JWKThumbprint::get() const
{
    return Base64URL::encode(value_);
}

vector<unsigned char> JWKThumbprint::computeRaw(JWK const &key, string const &algorithm)
{
    string const canonical_json = getCanonicalJWKJson(key);
    auto const hash_algorithm = getHashAlgorithm(algorithm);
    vector<unsigned char> const input(canonical_json.begin(), canonical_json.end());
    auto const &back_end = getBackEnd();
    return back_end.hash(hash_algorithm, input);
}

ostream &operator<<(ostream &os, JWKThumbprint const &thumbprint)
{
    os << thumbprint.get();
    return os;
}

bool operator==(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    auto const &lhs_raw = lhs.getRaw();
    auto const &rhs_raw = rhs.getRaw();
    return (lhs_raw.size() == rhs_raw.size()) &&
           equal(lhs_raw.begin(), lhs_raw.end(), rhs_raw.begin());
}

bool operator!=(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    return !(lhs == rhs);
}

bool operator<(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    auto const &lhs_raw = lhs.getRaw();
    auto const &rhs_raw = rhs.getRaw();
    return lexicographical_compare(lhs_raw.begin(), lhs_raw.end(), rhs_raw.begin(), rhs_raw.end());
}

bool operator<=(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    auto const &lhs_raw = lhs.getRaw();
    auto const &rhs_raw = rhs.getRaw();
    return !lexicographical_compare(rhs_raw.begin(), rhs_raw.end(), lhs_raw.begin(), lhs_raw.end());
}

bool operator>(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    auto const &lhs_raw = lhs.getRaw();
    auto const &rhs_raw = rhs.getRaw();
    return lexicographical_compare(rhs_raw.begin(), rhs_raw.end(), lhs_raw.begin(), lhs_raw.end());
}

bool operator>=(JWKThumbprint const &lhs, JWKThumbprint const &rhs)
{
    auto const &lhs_raw = lhs.getRaw();
    auto const &rhs_raw = rhs.getRaw();
    return !lexicographical_compare(lhs_raw.begin(), lhs_raw.end(), rhs_raw.begin(), rhs_raw.end());
}

}  // namespace JOSE
}  // namespace Vlinder
