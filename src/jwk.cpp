#include "jose/jwk.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <cstring>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"

namespace Vlinder {
namespace jose {

struct JWK::Impl
{
    KeyType keyType;
    EVP_PKEY* pkey = nullptr;
    std::string kid;
    std::string alg;
    Use use;
    bool hasUse = false;

    ~Impl()
    {
        if (pkey)
        {
            EVP_PKEY_free(pkey);
        }
    }

    Impl() : keyType(KeyType::RSA), use(Use::Signature)
    {
    }

    Impl(const Impl& other)
        : keyType(other.keyType), pkey(nullptr), kid(other.kid), alg(other.alg), use(other.use),
          hasUse(other.hasUse)
    {
        if (other.pkey)
        {
            pkey = EVP_PKEY_dup(other.pkey);
        }
    }
};

JWK::JWK() : impl_(std::make_unique<Impl>())
{
}

JWK::~JWK() = default;

JWK::JWK(const JWK& other) : impl_(std::make_unique<Impl>(*other.impl_))
{
}

JWK& JWK::operator=(const JWK& other)
{
    if (this != &other)
    {
        impl_ = std::make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWK::JWK(JWK&& other) noexcept = default;
JWK& JWK::operator=(JWK&& other) noexcept = default;

JWK JWK::generateRSA(int bits)
{
    JWK jwk;
    jwk.impl_->keyType = KeyType::RSA;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set key size");
    }

    if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);
    return jwk;
}

JWK JWK::generateEC(const std::string& curve)
{
    JWK jwk;
    jwk.impl_->keyType = KeyType::EC;

    int nid;
    if (curve == "P-256")
    {
        nid = NID_X9_62_prime256v1;
    }
    else if (curve == "P-384")
    {
        nid = NID_secp384r1;
    }
    else if (curve == "P-521")
    {
        nid = NID_secp521r1;
    }
    else
    {
        throw std::runtime_error("Unsupported curve");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set curve");
    }

    if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);
    return jwk;
}

JWK JWK::generateOct(int bits)
{
    JWK jwk;
    jwk.impl_->keyType = KeyType::oct;

    std::vector<unsigned char> key(bits / 8);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
    {
        throw std::runtime_error("Failed to generate random key");
    }

    jwk.impl_->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, key.data(), key.size());
    if (!jwk.impl_->pkey)
    {
        throw std::runtime_error("Failed to create symmetric key");
    }

    return jwk;
}

std::string JWK::toJson(bool includePrivate) const
{
    json jsonObj = json::object();

    // Set key type
    switch (impl_->keyType)
    {
        case KeyType::RSA:
            jsonObj["kty"] = "RSA";
            break;
        case KeyType::EC:
            jsonObj["kty"] = "EC";
            break;
        case KeyType::OKP:
            jsonObj["kty"] = "OKP";
            break;
        case KeyType::oct:
            jsonObj["kty"] = "oct";
            break;
    }

    // Add optional fields
    if (!impl_->kid.empty())
    {
        jsonObj["kid"] = impl_->kid;
    }

    if (!impl_->alg.empty())
    {
        jsonObj["alg"] = impl_->alg;
    }

    if (impl_->hasUse)
    {
        jsonObj["use"] = impl_->use == Use::Signature ? "sig" : "enc";
    }

    // Add key-specific fields
    if (impl_->keyType == KeyType::RSA && impl_->pkey)
    {
        // Use EVP_PKEY_get_bn_param for OpenSSL 3.0+
        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        BIGNUM* d = nullptr;
        
        EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_N, &n);
        EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_E, &e);
        
        if (n)
        {
            std::vector<unsigned char> nBytes(BN_num_bytes(n));
            BN_bn2bin(n, nBytes.data());
            jsonObj["n"] = Base64Url::encode(nBytes);
            BN_free(n);
        }

        if (e)
        {
            std::vector<unsigned char> eBytes(BN_num_bytes(e));
            BN_bn2bin(e, eBytes.data());
            jsonObj["e"] = Base64Url::encode(eBytes);
            BN_free(e);
        }

        if (includePrivate)
        {
            EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_D, &d);
            if (d)
            {
                std::vector<unsigned char> dBytes(BN_num_bytes(d));
                BN_bn2bin(d, dBytes.data());
                jsonObj["d"] = Base64Url::encode(dBytes);
                BN_free(d);

                BIGNUM *p = nullptr, *q = nullptr, *dmp1 = nullptr, *dmq1 = nullptr, *iqmp = nullptr;
                EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
                EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
                EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
                EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
                EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

                if (p)
                {
                    std::vector<unsigned char> pBytes(BN_num_bytes(p));
                    BN_bn2bin(p, pBytes.data());
                    jsonObj["p"] = Base64Url::encode(pBytes);
                    BN_free(p);
                }

                if (q)
                {
                    std::vector<unsigned char> qBytes(BN_num_bytes(q));
                    BN_bn2bin(q, qBytes.data());
                    jsonObj["q"] = Base64Url::encode(qBytes);
                    BN_free(q);
                }

                if (dmp1)
                {
                    std::vector<unsigned char> dp(BN_num_bytes(dmp1));
                    BN_bn2bin(dmp1, dp.data());
                    jsonObj["dp"] = Base64Url::encode(dp);
                    BN_free(dmp1);
                }

                if (dmq1)
                {
                    std::vector<unsigned char> dq(BN_num_bytes(dmq1));
                    BN_bn2bin(dmq1, dq.data());
                    jsonObj["dq"] = Base64Url::encode(dq);
                    BN_free(dmq1);
                }

                if (iqmp)
                {
                    std::vector<unsigned char> qi(BN_num_bytes(iqmp));
                    BN_bn2bin(iqmp, qi.data());
                    jsonObj["qi"] = Base64Url::encode(qi);
                    BN_free(iqmp);
                }
            }
        }
    }
    else if (impl_->keyType == KeyType::oct && impl_->pkey && includePrivate)
    {
        size_t len = 0;
        EVP_PKEY_get_raw_private_key(impl_->pkey, nullptr, &len);
        std::vector<unsigned char> key(len);
        EVP_PKEY_get_raw_private_key(impl_->pkey, key.data(), &len);
        jsonObj["k"] = Base64Url::encode(key);
    }

    return jsonObj.dump();
}

JWK JWK::fromJson(const std::string& jsonStr)
{
    JWK jwk;
    json jwkJson = json::parse(jsonStr);

    if (!jwkJson.contains("kty"))
    {
        throw std::runtime_error("Missing kty field");
    }

    std::string kty = jwkJson["kty"].get<std::string>();

    if (kty == "RSA")
    {
        jwk.impl_->keyType = KeyType::RSA;

        if (!jwkJson.contains("n") || !jwkJson.contains("e"))
        {
            throw std::runtime_error("Missing required RSA parameters");
        }

        auto nBytes = Base64Url::decode(jwkJson["n"].get<std::string>());
        auto eBytes = Base64Url::decode(jwkJson["e"].get<std::string>());

        BIGNUM* n = BN_bin2bn(nBytes.data(), static_cast<int>(nBytes.size()), nullptr);
        BIGNUM* e = BN_bin2bn(eBytes.data(), static_cast<int>(eBytes.size()), nullptr);

        // Use EVP_PKEY_CTX and OSSL_PARAM_BLD for OpenSSL 3.0+
        OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
        if (!param_bld)
        {
            BN_free(n);
            BN_free(e);
            throw std::runtime_error("Failed to create OSSL_PARAM_BLD");
        }

        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_N, n);
        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, e);

        if (jwkJson.contains("d"))
        {
            auto dBytes = Base64Url::decode(jwkJson["d"].get<std::string>());
            BIGNUM* d = BN_bin2bn(dBytes.data(), static_cast<int>(dBytes.size()), nullptr);
            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d);

            if (jwkJson.contains("p") && jwkJson.contains("q"))
            {
                auto pBytes = Base64Url::decode(jwkJson["p"].get<std::string>());
                auto qBytes = Base64Url::decode(jwkJson["q"].get<std::string>());
                BIGNUM* p = BN_bin2bn(pBytes.data(), static_cast<int>(pBytes.size()), nullptr);
                BIGNUM* q = BN_bin2bn(qBytes.data(), static_cast<int>(qBytes.size()), nullptr);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
                BN_free(p);
                BN_free(q);
            }
            BN_free(d);
        }

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(n);
        BN_free(e);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0)
        {
            OSSL_PARAM_free(params);
            if (ctx) EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize EVP_PKEY_CTX");
        }

        if (EVP_PKEY_fromdata(ctx, &jwk.impl_->pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        {
            OSSL_PARAM_free(params);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to create RSA key from parameters");
        }

        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
    }
    else if (kty == "oct")
    {
        jwk.impl_->keyType = KeyType::oct;

        if (!jwkJson.contains("k"))
        {
            throw std::runtime_error("Missing k parameter for symmetric key");
        }

        auto kBytes = Base64Url::decode(jwkJson["k"].get<std::string>());
        jwk.impl_->pkey =
            EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, kBytes.data(), kBytes.size());
    }

    if (jwkJson.contains("kid"))
    {
        jwk.impl_->kid = jwkJson["kid"].get<std::string>();
    }

    if (jwkJson.contains("alg"))
    {
        jwk.impl_->alg = jwkJson["alg"].get<std::string>();
    }

    if (jwkJson.contains("use"))
    {
        std::string use = jwkJson["use"].get<std::string>();
        jwk.impl_->hasUse = true;
        jwk.impl_->use = (use == "sig") ? Use::Signature : Use::Encryption;
    }

    return jwk;
}

JWK::KeyType JWK::getKeyType() const
{
    return impl_->keyType;
}

void JWK::setKeyId(const std::string& kid)
{
    impl_->kid = kid;
}

std::string JWK::getKeyId() const
{
    return impl_->kid;
}

void JWK::setUse(Use use)
{
    impl_->use = use;
    impl_->hasUse = true;
}

void JWK::setAlgorithm(const std::string& alg)
{
    impl_->alg = alg;
}

std::string JWK::getAlgorithm() const
{
    return impl_->alg;
}

bool JWK::hasPrivateKey() const
{
    if (!impl_->pkey)
    {
        return false;
    }

    if (impl_->keyType == KeyType::RSA)
    {
        BIGNUM* d = nullptr;
        if (EVP_PKEY_get_bn_param(impl_->pkey, OSSL_PKEY_PARAM_RSA_D, &d) > 0)
        {
            bool hasPrivate = (d != nullptr);
            BN_free(d);
            return hasPrivate;
        }
        return false;
    }
    else if (impl_->keyType == KeyType::oct)
    {
        return true;  // Symmetric keys always have "private" component
    }

    return false;
}

void* JWK::getKey() const
{
    return impl_->pkey;
}

// JWKSet implementation
struct JWKSet::Impl
{
    std::vector<JWK> keys;
};

JWKSet::JWKSet() : impl_(std::make_unique<Impl>())
{
}

JWKSet::~JWKSet() = default;

JWKSet JWKSet::fromJson(const std::string& jsonStr)
{
    JWKSet set;
    json jwkSetJson = json::parse(jsonStr);

    if (!jwkSetJson.contains("keys"))
    {
        throw std::runtime_error("Missing keys array");
    }

    // Note: Array access would need to be implemented in JsonValue
    // For now, simplified implementation

    return std::move(set);
}

void JWKSet::addKey(const JWK& key)
{
    impl_->keys.push_back(key);
}

JWK JWKSet::getKey(const std::string& kid) const
{
    for (const auto& key : impl_->keys)
    {
        if (key.getKeyId() == kid)
        {
            return key;
        }
    }
    throw std::runtime_error("Key not found");
}

std::vector<JWK> JWKSet::getKeys() const
{
    return impl_->keys;
}

std::string JWKSet::toJson() const
{
    json jsonObj = json::object();

    json keysArray = json::array();

    for (const auto& key : impl_->keys)
    {
        keysArray.push_back(json::parse(key.toJson(false)));
    }

    jsonObj["keys"] = keysArray;
    return jsonObj.dump();
}

}  // namespace jose
}  // namespace Vlinder
