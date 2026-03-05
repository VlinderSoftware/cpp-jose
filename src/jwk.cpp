#include "jwk.hpp"

#include <cstring>
#include <stdexcept>
#include <set>

#include "base64url.hpp"
#include "jwk_thumbprint.hpp"
#include "private/json_utils.hpp"
#include "private/back_end_factory.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

namespace {

// Default algorithms for key type + use combinations
string getDefaultAlgorithm(JWK::KeyType key_type, JWK::Use use, const string& curve = "")
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
    
    throw runtime_error("Unsupported key type for default algorithm");
}

// Validate algorithm for key type + use combination
void validateAlgorithm(const string& alg, JWK::KeyType key_type, JWK::Use use)
{
    static const set<string> rsa_sig_algs = {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
    };
    static const set<string> rsa_enc_algs = {
        "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA1_5"
    };
    static const set<string> ec_sig_algs = {
        "ES256", "ES384", "ES512", "ES256K"
    };
    static const set<string> ec_enc_algs = {
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
    };
    static const set<string> oct_sig_algs = {
        "HS256", "HS384", "HS512"
    };
    static const set<string> oct_enc_algs = {
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"
    };
    
    if (key_type == JWK::KeyType::rsa)
    {
        if (use == JWK::Use::signature && rsa_sig_algs.find(alg) == rsa_sig_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for RSA signature keys. Use: RS256, RS384, RS512, PS256, PS384, or PS512");
        }
        if (use == JWK::Use::encryption && rsa_enc_algs.find(alg) == rsa_enc_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for RSA encryption keys. Use: RSA-OAEP, RSA-OAEP-256, etc.");
        }
    }
    else if (key_type == JWK::KeyType::ec)
    {
        if (use == JWK::Use::signature && ec_sig_algs.find(alg) == ec_sig_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for EC signature keys. Use: ES256, ES384, ES512, or ES256K");
        }
        if (use == JWK::Use::encryption && ec_enc_algs.find(alg) == ec_enc_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for EC encryption keys. Use: ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, or ECDH-ES+A256KW");
        }
    }
    else if (key_type == JWK::KeyType::oct)
    {
        if (use == JWK::Use::signature && oct_sig_algs.find(alg) == oct_sig_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for symmetric signature keys. Use: HS256, HS384, or HS512");
        }
        if (use == JWK::Use::encryption && oct_enc_algs.find(alg) == oct_enc_algs.end())
        {
            throw runtime_error("Algorithm '" + alg + "' is not valid for symmetric encryption keys. Use: A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, or A256GCMKW");
        }
    }
}

JWK::Use inferUseFromAlgorithm(string const& alg)
{
    static set<string> const sig_algs = {
        "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512", "ES256K",
        "HS256", "HS384", "HS512"
    };
    static set<string> const enc_algs = {
        "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512", "RSA1_5",
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"
    };
    if (sig_algs.count(alg)) return JWK::Use::signature;
    if (enc_algs.count(alg)) return JWK::Use::encryption;
    throw runtime_error("Cannot infer 'use' from unknown algorithm: '" + alg + "'");
}

}  // anonymous namespace

struct JWK::Impl
{
    KeyType key_type_;
    unique_ptr<Private::Key> key_;
    string kid_;
    string alg_;
    Use use_;
    bool has_use_ = false;

    ~Impl() = default;

    Impl(KeyType key_type, Use use, string const& alg)
        : key_type_(key_type), use_(use), alg_(alg), has_use_(true)
    {
    }

    Impl(const Impl& other)
        : key_type_(other.key_type_), kid_(other.kid_), alg_(other.alg_), use_(other.use_),
          has_use_(other.has_use_)
    {
        if (other.key_)
        {
            key_ = other.key_->clone();
        }
    }
};

JWK::JWK(Impl &&impl)
{
    impl_ = make_unique<Impl>(move(impl));
}

JWK::~JWK() = default;

JWK::JWK(const JWK& other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWK& JWK::operator=(const JWK& other)
{
    if (this != &other)
    {
        impl_ = make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWK::JWK(JWK&& other) noexcept = default;
JWK& JWK::operator=(JWK&& other) noexcept = default;

JWK JWK::generateRSA(Use use, unsigned int bits, const string& alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::rsa, use) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::rsa, use);

    Impl impl(KeyType::rsa, use, final_alg);

    Private::BackEndFactory& factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = move(back_end->generateRSA(bits));

    JWK jwk(move(impl));

    return jwk;
}

JWK JWK::generateEC(Use use, const string& curve, const string& alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::ec, use, curve) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::ec, use);

    Impl impl(KeyType::ec, use, final_alg);

    Private::BackEndFactory& factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = move(back_end->generateEC(curve));

    JWK jwk(move(impl));

    return jwk;
}

JWK JWK::generateOct(Use use, int bits, const string& alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::oct, use) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::oct, use);

    Impl impl(KeyType::oct, use, final_alg);

    Private::BackEndFactory& factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = move(back_end->generateOct(bits));

    JWK jwk(move(impl));

    return jwk;
}

JWK JWK::generateOKP(Use use, unsigned int bits, const std::string& alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::okp, use) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::oct, use);

    if (0 == bits)
    {
        // Default key size based on use
        bits = (use == Use::signature) ? 192 : 768;  // For OKP, we can default to ML-DSA-65/ML-KEM-768
    }

    Impl impl(KeyType::okp, use, final_alg);

    Private::BackEndFactory& factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = move(back_end->generateOkp(use, bits));

    JWK jwk(move(impl));

    return jwk;
}

string JWK::toJSON(bool include_private) const
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
    if (impl_->key_type_ == KeyType::rsa && impl_->key_)
    {
        auto rsa_key = dynamic_cast<Private::RSAKey*>(impl_->key_.get());
        auto n(rsa_key->getN());
        auto e(rsa_key->getE());

        if (!n.empty())
        {
            json_obj["n"] = Base64Url::encode(n);
        }
        if (!e.empty())
        {
            json_obj["e"] = Base64Url::encode(e);
        }

        if (include_private)
        {
            auto d(rsa_key->getD());
            auto p(rsa_key->getP());
            auto q(rsa_key->getQ());
            auto dp(rsa_key->getDp());
            auto dq(rsa_key->getDq());
            auto qi(rsa_key->getQi());
            if (!d.empty())
            {
                json_obj["d"] = Base64Url::encode(d);
            }
            if (!d.empty())
            {
                json_obj["p"] = Base64Url::encode(p);
            }
            if (!d.empty())
            {
                json_obj["q"] = Base64Url::encode(q);
            }
            if (!d.empty())
            {
                json_obj["dp"] = Base64Url::encode(dp);
            }
            if (!d.empty())
            {
                json_obj["dq"] = Base64Url::encode(dq);
            }
            if (!d.empty())
            {
                json_obj["qi"] = Base64Url::encode(qi);
            }
        }
    }
    else if (impl_->key_type_ == KeyType::ec && impl_->key_)
    {
        auto ec_key = dynamic_cast<Private::ECKey*>(impl_->key_.get());
        json_obj["crv"] = ec_key->getCurveName();

        auto x(ec_key->getX());
        auto y(ec_key->getY());
        auto d(ec_key->getD());

        if (!x.empty())
        {
            json_obj["x"] = Base64Url::encode(x);
        }
        if (!y.empty())
        {
            json_obj["y"] = Base64Url::encode(y);
        }
        if (include_private && !d.empty())
        {
            json_obj["d"] = Base64Url::encode(d);
        }
    }
    else if (impl_->key_type_ == KeyType::okp && impl_->key_)
    {
#if defined(JOSE_USE_CNG)
        throw runtime_error("Post-quantum keys are not supported with CNG backend -- use OpenSSL");
#endif
    }
    else if (impl_->key_type_ == KeyType::oct && impl_->key_ && include_private)
    {
        auto oct_key = dynamic_cast<Private::OctKey*>(impl_->key_.get());
        auto k(oct_key->getK());
        if (!k.empty())
        {
            json_obj["k"] = Base64Url::encode(k);
        }
    }
    if (impl_->kid_.empty())
    {
        // Auto-generate kid as thumbprint if not set
        //TODO impl_->kid_ = generateThumbprint(json_obj);
    }
    json_obj["kid"] = impl_->kid_;

    return json_obj.dump();
}

JWK JWK::fromJSON(const string &json_str, bool permissive)
{
    json jwk_json = json::parse(json_str);

    if (!jwk_json.contains("kty"))
    {
        throw runtime_error("Missing kty field");
    }

    string kty = jwk_json["kty"].get<string>();
    if (!permissive && kty != "RSA" && kty != "EC" && kty != "oct" && kty != "okp")
    {
        throw runtime_error("Unsupported key type: " + kty);
    }
    if (permissive)
    {
        auto lower_kty(kty);
        // Allow case-insensitive kty values in permissive mode
        transform(lower_kty.begin(), lower_kty.end(), lower_kty.begin(), ::tolower);
        if (lower_kty == "rsa")
        {
            kty = "RSA";
        }
        else if (lower_kty == "ec")
        {
            kty = "EC";
        }
        else if (lower_kty == "oct")
        {
            kty = "oct";
        }
        else if (lower_kty == "okp")
        {
            kty = "OKP";
        }
        else
        {
            throw runtime_error("Unsupported key type: " + kty);
        }
    }
    KeyType key_type;
    bool has_use(jwk_json.contains("use"));
    Use use(has_use ? jwk_json["use"].get<string>() == "sig" ? Use::signature : Use::encryption
                    : Use::signature);
    string alg(jwk_json.contains("alg") ? jwk_json["alg"].get<string>() : "");

    // We need either the algorithm or the use. If neither is present, we won't know how to use the
    // key. If both are present, we'll validate that they are compatible. But if only one is
    // present, we can infer the other.
    if (!has_use && alg.empty())
    {
        throw runtime_error("JWK must contain at least one of 'use' or 'alg'");
    }

    // Derive key_type from kty for use in validation and inference
    if      (kty == "RSA") key_type = KeyType::rsa;
    else if (kty == "EC")  key_type = KeyType::ec;
    else if (kty == "oct") key_type = KeyType::oct;
    else                   key_type = KeyType::okp;

    string ec_curve;
    if (key_type == KeyType::ec)
    {
        if (!jwk_json.contains("crv"))
        {
            throw runtime_error("Missing required 'crv' parameter for EC key");
        }
        ec_curve = jwk_json["crv"].get<string>();
    }

    if (has_use && !alg.empty())
    {
        validateAlgorithm(alg, key_type, use);
    }
    else if (!has_use)
    {
        // Only alg present: infer use from the algorithm
        use = inferUseFromAlgorithm(alg);
        has_use = true;
    }
    else
    {
        // Only use present: infer alg from use.
        // For EC signature keys the curve drives the default (P-256→ES256, P-384→ES384,
        // P-521→ES512), so pass ec_curve. For EC encryption the result is always ECDH-ES
        // regardless of curve — the curve is carried in the key's 'crv' field, not the alg name.
        alg = getDefaultAlgorithm(key_type, use, ec_curve);
    }

    Private::BackEndFactory& factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    Impl impl(key_type, use, alg);
    if (jwk_json.contains("kid"))
    {
        impl.kid_ = jwk_json["kid"].get<string>();
    }

    switch (key_type)
    {
        case KeyType::rsa:
        {
            if (!jwk_json.contains("n") || !jwk_json.contains("e"))
            {
                throw runtime_error("Missing required RSA parameters");
            }
            auto n_bytes = Base64Url::decode(jwk_json["n"].get<string>());
            auto e_bytes = Base64Url::decode(jwk_json["e"].get<string>());
            auto d_bytes = jwk_json.contains("d") ? Base64Url::decode(jwk_json["d"].get<string>())
                                                  : vector<unsigned char>{};
            auto p_bytes = jwk_json.contains("p") ? Base64Url::decode(jwk_json["p"].get<string>())
                                                  : vector<unsigned char>{};
            auto q_bytes = jwk_json.contains("q") ? Base64Url::decode(jwk_json["q"].get<string>())
                                                  : vector<unsigned char>{};
            auto dp_bytes = jwk_json.contains("dp") ? Base64Url::decode(jwk_json["dp"].get<string>())
                                                  : vector<unsigned char>{};
            auto dq_bytes = jwk_json.contains("dq") ? Base64Url::decode(jwk_json["dq"].get<string>())
                                                  : vector<unsigned char>{};
            auto qi_bytes = jwk_json.contains("qi") ? Base64Url::decode(jwk_json["qi"].get<string>())
                                                  : vector<unsigned char>{};
            impl.key_ = move(back_end->generateRSA(n_bytes, e_bytes, d_bytes, p_bytes, q_bytes,
                                                     dp_bytes, dq_bytes, qi_bytes));
            break;
        }
        case KeyType::ec:
        case KeyType::okp:
        case KeyType::oct:
            break;
    }

    //else if (kty == "EC")
    //{
    //    jwk.impl_->key_type_ = KeyType::ec;

    //    if (!jwk_json.contains("crv") || !jwk_json.contains("x") || !jwk_json.contains("y"))
    //    {
    //        throw runtime_error("Missing required EC parameters");
    //    }

    //    string crv = jwk_json["crv"].get<string>();
    //    auto x_bytes = Base64Url::decode(jwk_json["x"].get<string>());
    //    auto y_bytes = Base64Url::decode(jwk_json["y"].get<string>());

    //    // Convert JWK curve names to OpenSSL curve names
    //    string group_name;
    //    if (crv == "P-256")
    //    {
    //        group_name = "prime256v1";
    //    }
    //    else if (crv == "P-384")
    //    {
    //        group_name = "secp384r1";
    //    }
    //    else if (crv == "P-521")
    //    {
    //        group_name = "secp521r1";
    //    }
    //    else
    //    {
    //        throw runtime_error("Unsupported EC curve: " + crv);
    //    }

    //    // Encode public key as uncompressed point: 0x04 || X || Y
    //    vector<unsigned char> pub_key;
    //    pub_key.push_back(0x04);  // uncompressed point format
    //    pub_key.insert(pub_key.end(), x_bytes.begin(), x_bytes.end());
    //    pub_key.insert(pub_key.end(), y_bytes.begin(), y_bytes.end());

    //    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    //    if (!param_bld)
    //    {
    //        throw runtime_error("Failed to create OSSL_PARAM_BLD");
    //    }

    //    OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, 
    //                                    group_name.c_str(), 0);
    //    OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, 
    //                                     pub_key.data(), pub_key.size());

    //    // Include private key if present
    //    BIGNUM* d = nullptr;
    //    if (jwk_json.contains("d"))
    //    {
    //        auto d_bytes = Base64Url::decode(jwk_json["d"].get<string>());
    //        d = BN_bin2bn(d_bytes.data(), static_cast<int>(d_bytes.size()), nullptr);
    //        OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, d);
    //    }

    //    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
    //    OSSL_PARAM_BLD_free(param_bld);
    //    
    //    // Free the BIGNUM after params are built
    //    if (d)
    //    {
    //        BN_free(d);
    //    }

    //    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    //    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0)
    //    {
    //        OSSL_PARAM_free(params);
    //        if (ctx) EVP_PKEY_CTX_free(ctx);
    //        throw runtime_error("Failed to initialize EVP_PKEY_CTX");
    //    }

    //    int selection = jwk_json.contains("d") ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    //    if (EVP_PKEY_fromdata(ctx, &jwk.impl_->pkey_, selection, params) <= 0)
    //    {
    //        OSSL_PARAM_free(params);
    //        EVP_PKEY_CTX_free(ctx);
    //        throw runtime_error("Failed to create EC key from parameters");
    //    }

    //    OSSL_PARAM_free(params);
    //    EVP_PKEY_CTX_free(ctx);
    //}
    //else if (kty == "oct")
    //{
    //    jwk.impl_->key_type_ = KeyType::oct;

    //    if (!jwk_json.contains("k"))
    //    {
    //        throw runtime_error("Missing k parameter for symmetric key");
    //    }

    //    auto k_bytes = Base64Url::decode(jwk_json["k"].get<string>());
    //    jwk.impl_->pkey_ =
    //        EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, k_bytes.data(), k_bytes.size());
    //}

    return JWK(move(impl));
}

JWK::KeyType JWK::getKeyType() const
{
    return impl_->key_type_;
}

void JWK::setKeyID(const string& kid)
{
    impl_->kid_ = kid;
}

string JWK::getKeyID() const
{
    return impl_->kid_;
}

void JWK::setUse(Use use)
{
    impl_->use_ = use;
    impl_->has_use_ = true;
}

void JWK::setAlgorithm(const string& alg)
{
    impl_->alg_ = alg;
}

string JWK::getAlgorithm() const
{
    return impl_->alg_;
}

bool JWK::hasPrivateKey() const
{
    if (!impl_->key_)
    {
        return false;
    }
    else
    {
        return impl_->key_->hasPrivate();
    }


    //if (impl_->key_type_ == KeyType::rsa)
    //{
    //    BIGNUM* d = nullptr;
    //    if (EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_D, &d) > 0)
    //    {
    //        bool has_private = (d != nullptr);
    //        BN_free(d);
    //        return has_private;
    //    }
    //    return false;
    //}
    //else if (impl_->key_type_ == KeyType::ec)
    //{
    //    BIGNUM* d = nullptr;
    //    if (EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_PRIV_KEY, &d) > 0)
    //    {
    //        bool has_private = (d != nullptr);
    //        BN_free(d);
    //        return has_private;
    //    }
    //    return false;
    //}
    //else if (impl_->key_type_ == KeyType::oct)
    //{
    //    return true;  // Symmetric keys always have "private" component
    //}

    //return false;
}

// JWKSet implementation
struct JWKSet::Impl
{
    vector<JWK> keys_;
};

JWKSet::JWKSet() : impl_(make_unique<Impl>())
{
}

JWKSet::~JWKSet() = default;

JWKSet JWKSet::fromJSON(const string& json_str)
{
    JWKSet set;
    json jwk_set_json = json::parse(json_str);

    if (!jwk_set_json.contains("keys"))
    {
        throw runtime_error("Missing keys array");
    }

    if (!jwk_set_json["keys"].is_array())
    {
        throw runtime_error("keys field must be an array");
    }

    // Parse each key in the array
    for (const auto& keyJson : jwk_set_json["keys"])
    {
        string keyJsonStr = keyJson.dump();
        JWK key = JWK::fromJSON(keyJsonStr);
        set.addKey(key);
    }

    return set;
}

void JWKSet::addKey(const JWK& key)
{
    impl_->keys_.push_back(key);
}

JWK JWKSet::getKey(const string& kid) const
{
    for (const auto& key : impl_->keys_)
    {
        if (key.getKeyID() == kid)
        {
            return key;
        }
    }
    throw runtime_error("Key not found");
}

vector<JWK> JWKSet::getKeys() const
{
    return impl_->keys_;
}

string JWKSet::toJSON() const
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
