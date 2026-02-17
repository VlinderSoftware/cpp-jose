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
#include <set>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwk_thumbprint.hpp"

namespace Vlinder {
namespace JOSE {

namespace {

// Default algorithms for key type + use combinations
std::string getDefaultAlgorithm(JWK::KeyType key_type, JWK::Use use, const std::string& curve = "")
{
    if (key_type == JWK::KeyType::rsa)
    {
        return (use == JWK::Use::signature) ? "RS256" : "RSA-OAEP-256";
    }
    else if (key_type == JWK::KeyType::ec)
    {
        if (use == JWK::Use::encryption)
        {
            return "ECDH-ES";  // Default ECDH key agreement algorithm
        }
        
        // Default based on curve for signature
        if (curve == "P-256") return "ES256";
        if (curve == "P-384") return "ES384";
        if (curve == "P-521") return "ES512";
        return "ES256"; // fallback
    }
    else if (key_type == JWK::KeyType::oct)
    {
        return (use == JWK::Use::signature) ? "HS256" : "A256KW";
    }
    
    throw std::runtime_error("Unsupported key type for default algorithm");
}

// Validate algorithm for key type + use combination
void validateAlgorithm(const std::string& alg, JWK::KeyType key_type, JWK::Use use)
{
    static const std::set<std::string> rsa_sig_algs = {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
    };
    static const std::set<std::string> rsa_enc_algs = {
        "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA1_5"
    };
    static const std::set<std::string> ec_sig_algs = {
        "ES256", "ES384", "ES512", "ES256K"
    };
    static const std::set<std::string> ec_enc_algs = {
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
    };
    static const std::set<std::string> oct_sig_algs = {
        "HS256", "HS384", "HS512"
    };
    static const std::set<std::string> oct_enc_algs = {
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"
    };
    
    if (key_type == JWK::KeyType::rsa)
    {
        if (use == JWK::Use::signature && rsa_sig_algs.find(alg) == rsa_sig_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for RSA signature keys. Use: RS256, RS384, RS512, PS256, PS384, or PS512");
        }
        if (use == JWK::Use::encryption && rsa_enc_algs.find(alg) == rsa_enc_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for RSA encryption keys. Use: RSA-OAEP, RSA-OAEP-256, etc.");
        }
    }
    else if (key_type == JWK::KeyType::ec)
    {
        if (use == JWK::Use::signature && ec_sig_algs.find(alg) == ec_sig_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for EC signature keys. Use: ES256, ES384, ES512, or ES256K");
        }
        if (use == JWK::Use::encryption && ec_enc_algs.find(alg) == ec_enc_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for EC encryption keys. Use: ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, or ECDH-ES+A256KW");
        }
    }
    else if (key_type == JWK::KeyType::oct)
    {
        if (use == JWK::Use::signature && oct_sig_algs.find(alg) == oct_sig_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for symmetric signature keys. Use: HS256, HS384, or HS512");
        }
        if (use == JWK::Use::encryption && oct_enc_algs.find(alg) == oct_enc_algs.end())
        {
            throw std::runtime_error("Algorithm '" + alg + "' is not valid for symmetric encryption keys. Use: A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, or A256GCMKW");
        }
    }
}

}  // anonymous namespace

struct JWK::Impl
{
    KeyType key_type_;
    EVP_PKEY* pkey_ = nullptr;
    std::string kid_;
    std::string alg_;
    Use use_;
    bool has_use_ = false;

    ~Impl()
    {
        if (pkey_)
        {
            EVP_PKEY_free(pkey_);
        }
    }

    Impl() : key_type_(KeyType::rsa), use_(Use::signature)
    {
    }

    Impl(const Impl& other)
        : key_type_(other.key_type_), pkey_(nullptr), kid_(other.kid_), alg_(other.alg_), use_(other.use_),
          has_use_(other.has_use_)
    {
        if (other.pkey_)
        {
            pkey_ = EVP_PKEY_dup(other.pkey_);
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

JWK JWK::generateRSA(Use use, int bits, const std::string& alg)
{
    JWK jwk;
    jwk.impl_->key_type_ = KeyType::rsa;

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

    if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey_) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);
    
    // Automatically set key ID to SHA-512 thumbprint of the public key
    jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");
    
    // Determine algorithm: use provided or default
    std::string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::rsa, use) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::rsa, use);
    
    // Set metadata
    jwk.impl_->alg_ = final_alg;
    jwk.impl_->use_ = use;
    jwk.impl_->has_use_ = true;
    
    return jwk;
}

JWK JWK::generateEC(Use use, const std::string& curve, const std::string& alg)
{
    JWK jwk;
    jwk.impl_->key_type_ = KeyType::ec;

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

    if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey_) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);
    
    // Automatically set key ID to SHA-512 thumbprint of the public key
    jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");
    
    // Determine algorithm: use provided or default based on curve
    std::string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::ec, use, curve) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::ec, use);
    
    // Set metadata
    jwk.impl_->alg_ = final_alg;
    jwk.impl_->use_ = use;
    jwk.impl_->has_use_ = true;
    
    return jwk;
}

JWK JWK::generateOct(Use use, int bits, const std::string& alg)
{
    JWK jwk;
    jwk.impl_->key_type_ = KeyType::oct;

    std::vector<unsigned char> key(bits / 8);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
    {
        throw std::runtime_error("Failed to generate random key");
    }

    jwk.impl_->pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, key.data(), key.size());
    if (!jwk.impl_->pkey_)
    {
        throw std::runtime_error("Failed to create symmetric key");
    }

    // Automatically set key ID to SHA-512 thumbprint
    jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");

    // Determine algorithm: use provided or default
    std::string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::oct, use) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::oct, use);
    
    // Set metadata
    jwk.impl_->alg_ = final_alg;
    jwk.impl_->use_ = use;
    jwk.impl_->has_use_ = true;

    return jwk;
}

std::string JWK::toJSON(bool include_private) const
{
    json json_obj = json::object();

    // Set key type
    switch (impl_->key_type_)
    {
        case KeyType::rsa:
            json_obj["kty"] = "RSA";
            break;
        case KeyType::ec:
            json_obj["kty"] = "EC";
            break;
        case KeyType::okp:
            json_obj["kty"] = "OKP";
            break;
        case KeyType::oct:
            json_obj["kty"] = "oct";
            break;
    }

    // Add optional fields
    if (!impl_->kid_.empty())
    {
        json_obj["kid"] = impl_->kid_;
    }

    if (!impl_->alg_.empty())
    {
        json_obj["alg"] = impl_->alg_;
    }

    if (impl_->has_use_)
    {
        json_obj["use"] = impl_->use_ == Use::signature ? "sig" : "enc";
    }

    // Add key-specific fields
    if (impl_->key_type_ == KeyType::rsa && impl_->pkey_)
    {
        // Use EVP_PKEY_get_bn_param for OpenSSL 3.0+
        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        BIGNUM* d = nullptr;
        
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_N, &n);
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_E, &e);
        
        if (n)
        {
            std::vector<unsigned char> n_bytes(BN_num_bytes(n));
            BN_bn2bin(n, n_bytes.data());
            json_obj["n"] = Base64Url::encode(n_bytes);
            BN_free(n);
        }

        if (e)
        {
            std::vector<unsigned char> e_bytes(BN_num_bytes(e));
            BN_bn2bin(e, e_bytes.data());
            json_obj["e"] = Base64Url::encode(e_bytes);
            BN_free(e);
        }

        if (include_private)
        {
            EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_D, &d);
            if (d)
            {
                std::vector<unsigned char> d_bytes(BN_num_bytes(d));
                BN_bn2bin(d, d_bytes.data());
                json_obj["d"] = Base64Url::encode(d_bytes);
                BN_free(d);

                BIGNUM *p = nullptr, *q = nullptr, *dmp1 = nullptr, *dmq1 = nullptr, *iqmp = nullptr;
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

                if (p)
                {
                    std::vector<unsigned char> p_bytes(BN_num_bytes(p));
                    BN_bn2bin(p, p_bytes.data());
                    json_obj["p"] = Base64Url::encode(p_bytes);
                    BN_free(p);
                }

                if (q)
                {
                    std::vector<unsigned char> q_bytes(BN_num_bytes(q));
                    BN_bn2bin(q, q_bytes.data());
                    json_obj["q"] = Base64Url::encode(q_bytes);
                    BN_free(q);
                }

                if (dmp1)
                {
                    std::vector<unsigned char> dp(BN_num_bytes(dmp1));
                    BN_bn2bin(dmp1, dp.data());
                    json_obj["dp"] = Base64Url::encode(dp);
                    BN_free(dmp1);
                }

                if (dmq1)
                {
                    std::vector<unsigned char> dq(BN_num_bytes(dmq1));
                    BN_bn2bin(dmq1, dq.data());
                    json_obj["dq"] = Base64Url::encode(dq);
                    BN_free(dmq1);
                }

                if (iqmp)
                {
                    std::vector<unsigned char> qi(BN_num_bytes(iqmp));
                    BN_bn2bin(iqmp, qi.data());
                    json_obj["qi"] = Base64Url::encode(qi);
                    BN_free(iqmp);
                }
            }
        }
    }
    else if (impl_->key_type_ == KeyType::ec && impl_->pkey_)
    {
        // Get the curve name
        char curve_name[80];
        size_t curve_name_len = sizeof(curve_name);
        std::string group_name;
        size_t key_size = 0;  // Expected byte size for coordinates
        
        if (EVP_PKEY_get_utf8_string_param(impl_->pkey_, OSSL_PKEY_PARAM_GROUP_NAME, 
                                           curve_name, sizeof(curve_name), &curve_name_len))
        {
            group_name = std::string(curve_name);
            // Convert OpenSSL curve names to JWK curve names
            if (group_name == "prime256v1")
            {
                json_obj["crv"] = "P-256";
                key_size = 32;
            }
            else if (group_name == "secp384r1")
            {
                json_obj["crv"] = "P-384";
                key_size = 48;
            }
            else if (group_name == "secp521r1")
            {
                json_obj["crv"] = "P-521";
                key_size = 66;
            }
            else
            {
                json_obj["crv"] = group_name;  // Use as-is if unknown
            }
        }

        // Get the public key coordinates (x, y)
        BIGNUM* x = nullptr;
        BIGNUM* y = nullptr;
        
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_EC_PUB_X, &x);
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
        
        if (x && key_size > 0)
        {
            std::vector<unsigned char> x_bytes(key_size, 0);
            int x_len = BN_num_bytes(x);
            // Pad with leading zeros if necessary
            BN_bn2bin(x, x_bytes.data() + (key_size - x_len));
            json_obj["x"] = Base64Url::encode(x_bytes);
            BN_free(x);
        }

        if (y && key_size > 0)
        {
            std::vector<unsigned char> y_bytes(key_size, 0);
            int y_len = BN_num_bytes(y);
            // Pad with leading zeros if necessary
            BN_bn2bin(y, y_bytes.data() + (key_size - y_len));
            json_obj["y"] = Base64Url::encode(y_bytes);
            BN_free(y);
        }

        // Include private key if requested
        if (include_private && key_size > 0)
        {
            BIGNUM* d = nullptr;
            EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_PRIV_KEY, &d);
            if (d)
            {
                std::vector<unsigned char> d_bytes(key_size, 0);
                int d_len = BN_num_bytes(d);
                // Pad with leading zeros if necessary
                BN_bn2bin(d, d_bytes.data() + (key_size - d_len));
                json_obj["d"] = Base64Url::encode(d_bytes);
                BN_free(d);
            }
        }
    }
    else if (impl_->key_type_ == KeyType::oct && impl_->pkey_ && include_private)
    {
        size_t len = 0;
        EVP_PKEY_get_raw_private_key(impl_->pkey_, nullptr, &len);
        std::vector<unsigned char> key(len);
        EVP_PKEY_get_raw_private_key(impl_->pkey_, key.data(), &len);
        json_obj["k"] = Base64Url::encode(key);
    }

    return json_obj.dump();
}

JWK JWK::fromJSON(const std::string& json_str)
{
    JWK jwk;
    json jwk_json = json::parse(json_str);

    if (!jwk_json.contains("kty"))
    {
        throw std::runtime_error("Missing kty field");
    }

    std::string kty = jwk_json["kty"].get<std::string>();

    if (kty == "RSA")
    {
        jwk.impl_->key_type_ = KeyType::rsa;

        if (!jwk_json.contains("n") || !jwk_json.contains("e"))
        {
            throw std::runtime_error("Missing required RSA parameters");
        }

        auto n_bytes = Base64Url::decode(jwk_json["n"].get<std::string>());
        auto e_bytes = Base64Url::decode(jwk_json["e"].get<std::string>());

        BIGNUM* n = BN_bin2bn(n_bytes.data(), static_cast<int>(n_bytes.size()), nullptr);
        BIGNUM* e = BN_bin2bn(e_bytes.data(), static_cast<int>(e_bytes.size()), nullptr);

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

        BIGNUM* d = nullptr;
        BIGNUM* p = nullptr;
        BIGNUM* q = nullptr;
        
        if (jwk_json.contains("d"))
        {
            auto d_bytes = Base64Url::decode(jwk_json["d"].get<std::string>());
            d = BN_bin2bn(d_bytes.data(), static_cast<int>(d_bytes.size()), nullptr);
            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_D, d);

            if (jwk_json.contains("p") && jwk_json.contains("q"))
            {
                auto p_bytes = Base64Url::decode(jwk_json["p"].get<std::string>());
                auto q_bytes = Base64Url::decode(jwk_json["q"].get<std::string>());
                p = BN_bin2bn(p_bytes.data(), static_cast<int>(p_bytes.size()), nullptr);
                q = BN_bin2bn(q_bytes.data(), static_cast<int>(q_bytes.size()), nullptr);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
                OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
            }
        }

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
        OSSL_PARAM_BLD_free(param_bld);
        
        // Free all BIGNUMs after params are built
        BN_free(n);
        BN_free(e);
        if (d) BN_free(d);
        if (p) BN_free(p);
        if (q) BN_free(q);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0)
        {
            OSSL_PARAM_free(params);
            if (ctx) EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize EVP_PKEY_CTX");
        }

        if (EVP_PKEY_fromdata(ctx, &jwk.impl_->pkey_, EVP_PKEY_KEYPAIR, params) <= 0)
        {
            OSSL_PARAM_free(params);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to create RSA key from parameters");
        }

        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
    }
    else if (kty == "EC")
    {
        jwk.impl_->key_type_ = KeyType::ec;

        if (!jwk_json.contains("crv") || !jwk_json.contains("x") || !jwk_json.contains("y"))
        {
            throw std::runtime_error("Missing required EC parameters");
        }

        std::string crv = jwk_json["crv"].get<std::string>();
        auto x_bytes = Base64Url::decode(jwk_json["x"].get<std::string>());
        auto y_bytes = Base64Url::decode(jwk_json["y"].get<std::string>());

        // Convert JWK curve names to OpenSSL curve names
        std::string group_name;
        if (crv == "P-256")
        {
            group_name = "prime256v1";
        }
        else if (crv == "P-384")
        {
            group_name = "secp384r1";
        }
        else if (crv == "P-521")
        {
            group_name = "secp521r1";
        }
        else
        {
            throw std::runtime_error("Unsupported EC curve: " + crv);
        }

        // Encode public key as uncompressed point: 0x04 || X || Y
        std::vector<unsigned char> pub_key;
        pub_key.push_back(0x04);  // uncompressed point format
        pub_key.insert(pub_key.end(), x_bytes.begin(), x_bytes.end());
        pub_key.insert(pub_key.end(), y_bytes.begin(), y_bytes.end());

        OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
        if (!param_bld)
        {
            throw std::runtime_error("Failed to create OSSL_PARAM_BLD");
        }

        OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, 
                                        group_name.c_str(), 0);
        OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, 
                                         pub_key.data(), pub_key.size());

        // Include private key if present
        BIGNUM* d = nullptr;
        if (jwk_json.contains("d"))
        {
            auto d_bytes = Base64Url::decode(jwk_json["d"].get<std::string>());
            d = BN_bin2bn(d_bytes.data(), static_cast<int>(d_bytes.size()), nullptr);
            OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
        }

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
        OSSL_PARAM_BLD_free(param_bld);
        
        // Free the BIGNUM after params are built
        if (d)
        {
            BN_free(d);
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0)
        {
            OSSL_PARAM_free(params);
            if (ctx) EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize EVP_PKEY_CTX");
        }

        int selection = jwk_json.contains("d") ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
        if (EVP_PKEY_fromdata(ctx, &jwk.impl_->pkey_, selection, params) <= 0)
        {
            OSSL_PARAM_free(params);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to create EC key from parameters");
        }

        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
    }
    else if (kty == "oct")
    {
        jwk.impl_->key_type_ = KeyType::oct;

        if (!jwk_json.contains("k"))
        {
            throw std::runtime_error("Missing k parameter for symmetric key");
        }

        auto k_bytes = Base64Url::decode(jwk_json["k"].get<std::string>());
        jwk.impl_->pkey_ =
            EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, k_bytes.data(), k_bytes.size());
    }

    if (jwk_json.contains("kid"))
    {
        jwk.impl_->kid_ = jwk_json["kid"].get<std::string>();
    }

    if (jwk_json.contains("alg"))
    {
        jwk.impl_->alg_ = jwk_json["alg"].get<std::string>();
    }

    if (jwk_json.contains("use"))
    {
        std::string use = jwk_json["use"].get<std::string>();
        jwk.impl_->has_use_ = true;
        jwk.impl_->use_ = (use == "sig") ? Use::signature : Use::encryption;
    }

    return jwk;
}

JWK::KeyType JWK::getKeyType() const
{
    return impl_->key_type_;
}

void JWK::setKeyID(const std::string& kid)
{
    impl_->kid_ = kid;
}

std::string JWK::getKeyID() const
{
    return impl_->kid_;
}

void JWK::setUse(Use use)
{
    impl_->use_ = use;
    impl_->has_use_ = true;
}

void JWK::setAlgorithm(const std::string& alg)
{
    impl_->alg_ = alg;
}

std::string JWK::getAlgorithm() const
{
    return impl_->alg_;
}

bool JWK::hasPrivateKey() const
{
    if (!impl_->pkey_)
    {
        return false;
    }

    if (impl_->key_type_ == KeyType::rsa)
    {
        BIGNUM* d = nullptr;
        if (EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_D, &d) > 0)
        {
            bool has_private = (d != nullptr);
            BN_free(d);
            return has_private;
        }
        return false;
    }
    else if (impl_->key_type_ == KeyType::ec)
    {
        BIGNUM* d = nullptr;
        if (EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_PRIV_KEY, &d) > 0)
        {
            bool has_private = (d != nullptr);
            BN_free(d);
            return has_private;
        }
        return false;
    }
    else if (impl_->key_type_ == KeyType::oct)
    {
        return true;  // Symmetric keys always have "private" component
    }

    return false;
}

void* JWK::getKey() const
{
    return impl_->pkey_;
}

// JWKSet implementation
struct JWKSet::Impl
{
    std::vector<JWK> keys_;
};

JWKSet::JWKSet() : impl_(std::make_unique<Impl>())
{
}

JWKSet::~JWKSet() = default;

JWKSet JWKSet::fromJSON(const std::string& json_str)
{
    JWKSet set;
    json jwk_set_json = json::parse(json_str);

    if (!jwk_set_json.contains("keys"))
    {
        throw std::runtime_error("Missing keys array");
    }

    if (!jwk_set_json["keys"].is_array())
    {
        throw std::runtime_error("keys field must be an array");
    }

    // Parse each key in the array
    for (const auto& keyJson : jwk_set_json["keys"])
    {
        std::string keyJsonStr = keyJson.dump();
        JWK key = JWK::fromJSON(keyJsonStr);
        set.addKey(key);
    }

    return set;
}

void JWKSet::addKey(const JWK& key)
{
    impl_->keys_.push_back(key);
}

JWK JWKSet::getKey(const std::string& kid) const
{
    for (const auto& key : impl_->keys_)
    {
        if (key.getKeyID() == kid)
        {
            return key;
        }
    }
    throw std::runtime_error("Key not found");
}

std::vector<JWK> JWKSet::getKeys() const
{
    return impl_->keys_;
}

std::string JWKSet::toJSON() const
{
    json json_obj = json::object();

    json keys_array = json::array();

    for (const auto& key : impl_->keys_)
    {
        keys_array.push_back(json::parse(key.toJSON(false)));
    }

    json_obj["keys"] = keys_array;
    return json_obj.dump();
}

}  // namespace JOSE
}  // namespace Vlinder
