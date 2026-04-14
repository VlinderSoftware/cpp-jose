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

// Extract required JWK components in lexicographic order per RFC 7638.
// Returns makeError on any missing required field; makeOk with the canonical JSON string otherwise.
Private::Result<string> getCanonicalJWKJson_(JWK const &key)
{
    bool const include_private = (key.getKeyType() == JWK::KeyType::oct);
    string const full_json = key.toJSON(include_private);
    json const jwk_value = json::parse(full_json);

    if (!jwk_value.contains("kty"))
        return Private::makeError<string>("JWK missing required 'kty' field");

    string const kty = jwk_value["kty"].get<string>();

    if (kty == "RSA")
    {
        if (!jwk_value.contains("e") || !jwk_value.contains("n"))
            return Private::makeError<string>("RSA JWK missing required fields");
        string const e = jwk_value["e"].get<string>();
        string const n = jwk_value["n"].get<string>();
        return Private::makeOk<string>("{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}");
    }
    if (kty == "EC")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x") || !jwk_value.contains("y"))
            return Private::makeError<string>("EC JWK missing required fields");
        string const crv = jwk_value["crv"].get<string>();
        string const x = jwk_value["x"].get<string>();
        string const y = jwk_value["y"].get<string>();
        return Private::makeOk<string>("{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x +
                                       "\",\"y\":\"" + y + "\"}");
    }
    if (kty == "oct")
    {
        if (!jwk_value.contains("k"))
            return Private::makeError<string>("oct JWK missing required 'k' field");
        string const k = jwk_value["k"].get<string>();
        return Private::makeOk<string>("{\"k\":\"" + k + "\",\"kty\":\"oct\"}");
    }
    if (kty == "OKP")
    {
        if (!jwk_value.contains("crv") || !jwk_value.contains("x"))
            return Private::makeError<string>("OKP JWK missing required fields");
        string const crv = jwk_value["crv"].get<string>();
        string const x = jwk_value["x"].get<string>();
        return Private::makeOk<string>("{\"crv\":\"" + crv + "\",\"kty\":\"OKP\",\"x\":\"" + x +
                                       "\"}");
    }
    return Private::makeError<string>("Unsupported key type: " + kty);
}

// Extract required JWK components in lexicographic order per RFC 7638
string getCanonicalJWKJson(JWK const &key)
{
    auto [json_opt, json_err] = getCanonicalJWKJson_(key);
    if (!json_opt)
        throw runtime_error(json_err);
    return *json_opt;
}

Private::Result<Private::HashAlgorithm> getHashAlgorithm_(string const &algorithm)
{
    if (algorithm == "SHA-256")
        return Private::makeOk<Private::HashAlgorithm>(Private::HashAlgorithm::sha256);
    if (algorithm == "SHA-384")
        return Private::makeOk<Private::HashAlgorithm>(Private::HashAlgorithm::sha384);
    if (algorithm == "SHA-512")
        return Private::makeOk<Private::HashAlgorithm>(Private::HashAlgorithm::sha512);
    return Private::makeError<Private::HashAlgorithm>("Unsupported hash algorithm: " + algorithm);
}

Private::HashAlgorithm getHashAlgorithm(string const &algorithm)
{
    auto [alg_opt, alg_err] = getHashAlgorithm_(algorithm);
    if (!alg_opt)
        throw runtime_error(alg_err);
    return *alg_opt;
}

// Nothrow core: compute the raw hash bytes for a JWK thumbprint.
Private::Result<vector<unsigned char>> computeRaw_(JWK const &key, string const &algorithm)
{
    auto [canonical_opt, canonical_err] = getCanonicalJWKJson_(key);
    if (!canonical_opt)
        return Private::makeError<vector<unsigned char>>(canonical_err);

    auto [hash_alg_opt, hash_alg_err] = getHashAlgorithm_(algorithm);
    if (!hash_alg_opt)
        return Private::makeError<vector<unsigned char>>(hash_alg_err);

    vector<unsigned char> const input(canonical_opt->begin(), canonical_opt->end());
    auto const &back_end = getBackEnd();
    auto [hash_opt, hash_err] = back_end.hash(*hash_alg_opt, input);
    if (!hash_opt)
        return Private::makeError<vector<unsigned char>>(hash_err);
    return Private::makeOk<vector<unsigned char>>(std::move(*hash_opt));
}

}  // anonymous namespace

JWKThumbprint JWKThumbprint::compute(JWK const &key, string const &algorithm)
{
    return JWKThumbprint(computeRaw(key, algorithm));
}

optional<JWKThumbprint>
JWKThumbprint::compute(JWK const &key, string const &algorithm, nothrow_t const &) noexcept
{
    auto [raw_opt, raw_err] = computeRaw_(key, algorithm);
    if (!raw_opt)
        return nullopt;
    return JWKThumbprint(*raw_opt);
}

string JWKThumbprint::get() const
{
    return Base64URL::encode(value_);
}

vector<unsigned char> JWKThumbprint::computeRaw(JWK const &key, string const &algorithm)
{
    auto [raw_opt, raw_err] = computeRaw_(key, algorithm);
    if (!raw_opt)
        throw runtime_error(raw_err);
    return std::move(*raw_opt);
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
