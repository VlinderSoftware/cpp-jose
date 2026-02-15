#include "jose/jwk_thumbprint.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <map>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwk.hpp"

namespace Vlinder {
namespace JOSE {

namespace {

std::string getOpenSSLError()
{
    unsigned long err = ERR_get_error();
    if (err == 0)
    {
        return "Unknown error";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// Extract required JWK components in lexicographic order per RFC 7638
std::string getCanonicalJWKJson(const JWK& key)
{
    // For symmetric (oct) keys, we need to include the private key material
    // For asymmetric keys, we only need the public key
    bool include_private = (key.getKeyType() == JWK::KeyType::oct);
    
    // Parse the full JWK JSON
    std::string full_json = key.toJSON(include_private);
    json jwk_value = json::parse(full_json);

    if (!jwk_value.contains("kty"))
    {
        throw std::runtime_error("JWK missing required 'kty' field");
    }

    std::string kty = jwk_value["kty"].get<std::string>();

    // Build canonical JSON with only required fields in lexicographic order
    // Per RFC 7638: Members must be ordered lexicographically

    json canonical = json::object();

    if (kty == "RSA")
    {
        // Required members for RSA: e, kty, n (lexicographic order: e, kty, n)
        if (!jwk_value.contains("e") || !jwk_value.contains("n"))
        {
            throw std::runtime_error("RSA JWK missing required fields");
        }

        // We need to build JSON in lexicographic order manually
        // e < k < n in ASCII
        std::string e = jwk_value["e"].get<std::string>();
        std::string n = jwk_value["n"].get<std::string>();

        // Manually construct the JSON to ensure exact ordering
        return "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
    }
    else if (kty == "EC")
    {
        // Required members for EC: crv, kty, x, y (lexicographic order: crv, kty, x, y)
        if (!jwk_value.contains("crv") || !jwk_value.contains("x") || !jwk_value.contains("y"))
        {
            throw std::runtime_error("EC JWK missing required fields");
        }

        std::string crv = jwk_value["crv"].get<std::string>();
        std::string x = jwk_value["x"].get<std::string>();
        std::string y = jwk_value["y"].get<std::string>();

        // Manually construct the JSON to ensure exact ordering
        // c < k < x < y in ASCII
        return "{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
    }
    else if (kty == "oct")
    {
        // Required members for oct: k, kty (lexicographic order: k, kty)
        if (!jwk_value.contains("k"))
        {
            throw std::runtime_error("oct JWK missing required 'k' field");
        }

        std::string k = jwk_value["k"].get<std::string>();

        // k < kty in ASCII
        return "{\"k\":\"" + k + "\",\"kty\":\"oct\"}";
    }
    else if (kty == "OKP")
    {
        // Required members for OKP: crv, kty, x (lexicographic order: crv, kty, x)
        if (!jwk_value.contains("crv") || !jwk_value.contains("x"))
        {
            throw std::runtime_error("OKP JWK missing required fields");
        }

        std::string crv = jwk_value["crv"].get<std::string>();
        std::string x = jwk_value["x"].get<std::string>();

        // c < k < x in ASCII
        return "{\"crv\":\"" + crv + "\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}";
    }
    else
    {
        throw std::runtime_error("Unsupported key type: " + kty);
    }
}

const EVP_MD* getHashAlgorithm(const std::string& algorithm)
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

std::string JWKThumbprint::compute(const JWK& key)
{
    return compute(key, "SHA-256");
}

std::string JWKThumbprint::compute(const JWK& key, const std::string& algorithm)
{
    std::vector<unsigned char> rawThumbprint = computeRaw(key, algorithm);
    return Base64Url::encode(rawThumbprint);
}

std::vector<unsigned char> JWKThumbprint::computeRaw(const JWK& key, const std::string& algorithm)
{
    // Get canonical JWK JSON representation
    std::string canonicalJson = getCanonicalJWKJson(key);

    // Get hash algorithm
    const EVP_MD* md = getHashAlgorithm(algorithm);
    if (!md)
    {
        throw std::runtime_error("Failed to get hash algorithm");
    }

    // Compute hash
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest: " + getOpenSSLError());
    }

    if (EVP_DigestUpdate(ctx, canonicalJson.data(), canonicalJson.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest: " + getOpenSSLError());
    }

    unsigned int hashLen = 0;
    std::vector<unsigned char> hash(EVP_MD_size(md));

    if (EVP_DigestFinal_ex(ctx, hash.data(), &hashLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize digest: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(ctx);

    hash.resize(hashLen);
    return hash;
}

}  // namespace JOSE
}  // namespace Vlinder
