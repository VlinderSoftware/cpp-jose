#include "jose/jwk_thumbprint.hpp"

#include <algorithm>
#include <map>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwk.hpp"
#include "details/backend.hpp"

namespace Vlinder {
namespace JOSE {

namespace {

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

const EVP_MD* getHashAlgorithm(std::string const &algorithm)
{
    if (algorithm == "SHA-256")
    {
        return EVP_sha256();
    }
    else if (algorithm == "SHA-384")
    {
        return EVP_sha384();
    }
    else if (algorithm == "SHA-512")
    {
        return EVP_sha512();
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
    const EVP_MD* md = getHashAlgorithm(algorithm);
    if (!md)
    {
        throw std::runtime_error("Failed to get hash algorithm");
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest: " + Details::OpenSSLBackend().getErrorString());
    }
    if (EVP_DigestUpdate(ctx, canonical_json.data(), canonical_json.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest: " + Details::OpenSSLBackend().getErrorString());
    }
    unsigned int hash_len = 0;
    std::vector<unsigned char> hash(EVP_MD_size(md));
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize digest: " + Details::OpenSSLBackend().getErrorString());
    }
    EVP_MD_CTX_free(ctx);
    hash.resize(hash_len);
    return hash;
}

}  // namespace JOSE
}  // namespace Vlinder
