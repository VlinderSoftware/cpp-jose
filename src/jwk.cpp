#include "jose/jwk.hpp"
#include "jose/json_utils.hpp"
#include "jose/base64url.hpp"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace Vlinder
{
namespace jose
{

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
    
    Impl() : keyType(KeyType::RSA), use(Use::Signature) {}
    
    Impl(const Impl& other) : keyType(other.keyType), pkey(nullptr), 
                               kid(other.kid), alg(other.alg), 
                               use(other.use), hasUse(other.hasUse)
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
    
    jwk.impl_->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, 
                                                    key.data(), key.size());
    if (!jwk.impl_->pkey)
    {
        throw std::runtime_error("Failed to create symmetric key");
    }
    
    return jwk;
}

std::string JWK::toJson(bool includePrivate) const
{
    JsonValue json;
    json.setObject();
    
    // Set key type
    switch (impl_->keyType)
    {
        case KeyType::RSA:
            json.set("kty", JsonValue("RSA"));
            break;
        case KeyType::EC:
            json.set("kty", JsonValue("EC"));
            break;
        case KeyType::OKP:
            json.set("kty", JsonValue("OKP"));
            break;
        case KeyType::oct:
            json.set("kty", JsonValue("oct"));
            break;
    }
    
    // Add optional fields
    if (!impl_->kid.empty())
    {
        json.set("kid", JsonValue(impl_->kid));
    }
    
    if (!impl_->alg.empty())
    {
        json.set("alg", JsonValue(impl_->alg));
    }
    
    if (impl_->hasUse)
    {
        json.set("use", JsonValue(impl_->use == Use::Signature ? "sig" : "enc"));
    }
    
    // Add key-specific fields
    if (impl_->keyType == KeyType::RSA && impl_->pkey)
    {
        RSA* rsa = EVP_PKEY_get1_RSA(impl_->pkey);
        if (rsa)
        {
            const BIGNUM *n, *e, *d;
            RSA_get0_key(rsa, &n, &e, &d);
            
            if (n)
            {
                std::vector<unsigned char> nBytes(BN_num_bytes(n));
                BN_bn2bin(n, nBytes.data());
                json.set("n", JsonValue(Base64Url::encode(nBytes)));
            }
            
            if (e)
            {
                std::vector<unsigned char> eBytes(BN_num_bytes(e));
                BN_bn2bin(e, eBytes.data());
                json.set("e", JsonValue(Base64Url::encode(eBytes)));
            }
            
            if (includePrivate && d)
            {
                std::vector<unsigned char> dBytes(BN_num_bytes(d));
                BN_bn2bin(d, dBytes.data());
                json.set("d", JsonValue(Base64Url::encode(dBytes)));
                
                const BIGNUM *p, *q, *dmp1, *dmq1, *iqmp;
                RSA_get0_factors(rsa, &p, &q);
                RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
                
                if (p)
                {
                    std::vector<unsigned char> pBytes(BN_num_bytes(p));
                    BN_bn2bin(p, pBytes.data());
                    json.set("p", JsonValue(Base64Url::encode(pBytes)));
                }
                
                if (q)
                {
                    std::vector<unsigned char> qBytes(BN_num_bytes(q));
                    BN_bn2bin(q, qBytes.data());
                    json.set("q", JsonValue(Base64Url::encode(qBytes)));
                }
                
                if (dmp1)
                {
                    std::vector<unsigned char> dp(BN_num_bytes(dmp1));
                    BN_bn2bin(dmp1, dp.data());
                    json.set("dp", JsonValue(Base64Url::encode(dp)));
                }
                
                if (dmq1)
                {
                    std::vector<unsigned char> dq(BN_num_bytes(dmq1));
                    BN_bn2bin(dmq1, dq.data());
                    json.set("dq", JsonValue(Base64Url::encode(dq)));
                }
                
                if (iqmp)
                {
                    std::vector<unsigned char> qi(BN_num_bytes(iqmp));
                    BN_bn2bin(iqmp, qi.data());
                    json.set("qi", JsonValue(Base64Url::encode(qi)));
                }
            }
            
            RSA_free(rsa);
        }
    }
    else if (impl_->keyType == KeyType::oct && impl_->pkey && includePrivate)
    {
        size_t len = 0;
        EVP_PKEY_get_raw_private_key(impl_->pkey, nullptr, &len);
        std::vector<unsigned char> key(len);
        EVP_PKEY_get_raw_private_key(impl_->pkey, key.data(), &len);
        json.set("k", JsonValue(Base64Url::encode(key)));
    }
    
    return json.serialize();
}

JWK JWK::fromJson(const std::string& jsonStr)
{
    JWK jwk;
    JsonValue json = JsonValue::parse(jsonStr);
    
    if (!json.has("kty"))
    {
        throw std::runtime_error("Missing kty field");
    }
    
    std::string kty = json["kty"].asString();
    
    if (kty == "RSA")
    {
        jwk.impl_->keyType = KeyType::RSA;
        
        if (!json.has("n") || !json.has("e"))
        {
            throw std::runtime_error("Missing required RSA parameters");
        }
        
        auto nBytes = Base64Url::decode(json["n"].asString());
        auto eBytes = Base64Url::decode(json["e"].asString());
        
        BIGNUM* n = BN_bin2bn(nBytes.data(), static_cast<int>(nBytes.size()), nullptr);
        BIGNUM* e = BN_bin2bn(eBytes.data(), static_cast<int>(eBytes.size()), nullptr);
        
        RSA* rsa = RSA_new();
        RSA_set0_key(rsa, n, e, nullptr);
        
        if (json.has("d"))
        {
            auto dBytes = Base64Url::decode(json["d"].asString());
            BIGNUM* d = BN_bin2bn(dBytes.data(), static_cast<int>(dBytes.size()), nullptr);
            RSA_set0_key(rsa, nullptr, nullptr, d);
            
            if (json.has("p") && json.has("q"))
            {
                auto pBytes = Base64Url::decode(json["p"].asString());
                auto qBytes = Base64Url::decode(json["q"].asString());
                BIGNUM* p = BN_bin2bn(pBytes.data(), static_cast<int>(pBytes.size()), nullptr);
                BIGNUM* q = BN_bin2bn(qBytes.data(), static_cast<int>(qBytes.size()), nullptr);
                RSA_set0_factors(rsa, p, q);
            }
        }
        
        jwk.impl_->pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(jwk.impl_->pkey, rsa);
    }
    else if (kty == "oct")
    {
        jwk.impl_->keyType = KeyType::oct;
        
        if (!json.has("k"))
        {
            throw std::runtime_error("Missing k parameter for symmetric key");
        }
        
        auto kBytes = Base64Url::decode(json["k"].asString());
        jwk.impl_->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                                        kBytes.data(), kBytes.size());
    }
    
    if (json.has("kid"))
    {
        jwk.impl_->kid = json["kid"].asString();
    }
    
    if (json.has("alg"))
    {
        jwk.impl_->alg = json["alg"].asString();
    }
    
    if (json.has("use"))
    {
        std::string use = json["use"].asString();
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
        RSA* rsa = EVP_PKEY_get1_RSA(impl_->pkey);
        if (rsa)
        {
            const BIGNUM *d;
            RSA_get0_key(rsa, nullptr, nullptr, &d);
            RSA_free(rsa);
            return d != nullptr;
        }
    }
    else if (impl_->keyType == KeyType::oct)
    {
        return true; // Symmetric keys always have "private" component
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
    JsonValue json = JsonValue::parse(jsonStr);
    
    if (!json.has("keys"))
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
    JsonValue json;
    json.setObject();
    
    JsonValue keys;
    keys.setArray();
    
    for (const auto& key : impl_->keys)
    {
        keys.append(JsonValue::parse(key.toJson(false)));
    }
    
    json.set("keys", keys);
    return json.serialize();
}

} // namespace jose
} // namespace Vlinder
