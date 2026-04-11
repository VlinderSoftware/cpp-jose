#include "jwk.hpp"

#include <cstring>
#include <set>
#include <stdexcept>

#include "base64url.hpp"
#include "jwk_impl.hpp"
#include "jwk_thumbprint.hpp"
#include "private/back_end_factory.hpp"
#include "private/json_utils.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

namespace {

// Default algorithms for key type + use combinations
string getDefaultAlgorithm(JWK::KeyType key_type, JWK::Use use, string const &curve = "")
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
        if (curve == "P-256")
            return "ES256";
        if (curve == "P-384")
            return "ES384";
        if (curve == "P-521")
            return "ES512";
        return "ES256";  // fallback
    }
    else if (key_type == JWK::KeyType::oct)
    {
        return (use == JWK::Use::signature) ? "HS256" : "A256KW";
    }
    else if (key_type == JWK::KeyType::okp)
    {
        return (use == JWK::Use::signature) ? "EdDSA" : "ECDH-ES";
    }

    throw runtime_error("Unsupported key type for default algorithm");
}

// Validate algorithm for key type + use combination
void validateAlgorithm(string const &alg, JWK::KeyType key_type, JWK::Use use)
{
    static set<string> const rsa_sig_algs = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"};
    static set<string> const rsa_enc_algs = {"RSA-OAEP",
                                             "RSA-OAEP-256",
                                             "RSA-OAEP-384",
                                             "RSA-OAEP-512",
                                             "RSA1_5"};
    static set<string> const ec_sig_algs = {"ES256", "ES384", "ES512", "ES256K"};
    static set<string> const ec_enc_algs = {"ECDH-ES",
                                            "ECDH-ES+A128KW",
                                            "ECDH-ES+A192KW",
                                            "ECDH-ES+A256KW"};
    static set<string> const oct_sig_algs = {"HS256", "HS384", "HS512"};
    static set<string> const oct_enc_algs =
        {"A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"};
    static set<string> const okp_sig_algs = {"EdDSA"};
    static set<string> const okp_enc_algs = {"ECDH-ES",
                                             "ECDH-ES+A128KW",
                                             "ECDH-ES+A192KW",
                                             "ECDH-ES+A256KW"};

    if (key_type == JWK::KeyType::rsa)
    {
        if (use == JWK::Use::signature && rsa_sig_algs.find(alg) == rsa_sig_algs.end())
        {
            throw runtime_error("Algorithm '" + alg +
                                "' is not valid for RSA signature keys. Use: RS256, RS384, RS512, "
                                "PS256, PS384, or PS512");
        }
        if (use == JWK::Use::encryption && rsa_enc_algs.find(alg) == rsa_enc_algs.end())
        {
            throw runtime_error(
                "Algorithm '" + alg +
                "' is not valid for RSA encryption keys. Use: RSA-OAEP, RSA-OAEP-256, etc.");
        }
    }
    else if (key_type == JWK::KeyType::ec)
    {
        if (use == JWK::Use::signature && ec_sig_algs.find(alg) == ec_sig_algs.end())
        {
            throw runtime_error(
                "Algorithm '" + alg +
                "' is not valid for EC signature keys. Use: ES256, ES384, ES512, or ES256K");
        }
        if (use == JWK::Use::encryption && ec_enc_algs.find(alg) == ec_enc_algs.end())
        {
            throw runtime_error("Algorithm '" + alg +
                                "' is not valid for EC encryption keys. Use: ECDH-ES, "
                                "ECDH-ES+A128KW, ECDH-ES+A192KW, or ECDH-ES+A256KW");
        }
    }
    else if (key_type == JWK::KeyType::oct)
    {
        if (use == JWK::Use::signature && oct_sig_algs.find(alg) == oct_sig_algs.end())
        {
            throw runtime_error(
                "Algorithm '" + alg +
                "' is not valid for symmetric signature keys. Use: HS256, HS384, or HS512");
        }
        if (use == JWK::Use::encryption && oct_enc_algs.find(alg) == oct_enc_algs.end())
        {
            throw runtime_error("Algorithm '" + alg +
                                "' is not valid for symmetric encryption keys. Use: A128KW, "
                                "A192KW, A256KW, A128GCMKW, A192GCMKW, or A256GCMKW");
        }
    }
    else if (key_type == JWK::KeyType::okp)
    {
        if (use == JWK::Use::signature && okp_sig_algs.find(alg) == okp_sig_algs.end())
        {
            throw runtime_error("Algorithm '" + alg +
                                "' is not valid for OKP signature keys. Use: EdDSA");
        }
        if (use == JWK::Use::encryption && okp_enc_algs.find(alg) == okp_enc_algs.end())
        {
            throw runtime_error(
                "Algorithm '" + alg +
                "' is not valid for OKP encryption keys. Use: ECDH-ES or ECDH-ES+AxxxKW");
        }
    }
}

JWK::Use inferUseFromAlgorithm(string const &alg)
{
    static set<string> const sig_algs = {"RS256",
                                         "RS384",
                                         "RS512",
                                         "PS256",
                                         "PS384",
                                         "PS512",
                                         "ES256",
                                         "ES384",
                                         "ES512",
                                         "ES256K",
                                         "EdDSA",
                                         "HS256",
                                         "HS384",
                                         "HS512"};
    static set<string> const enc_algs = {"RSA-OAEP",
                                         "RSA-OAEP-256",
                                         "RSA-OAEP-384",
                                         "RSA-OAEP-512",
                                         "RSA1_5",
                                         "ECDH-ES",
                                         "ECDH-ES+A128KW",
                                         "ECDH-ES+A192KW",
                                         "ECDH-ES+A256KW",
                                         "A128KW",
                                         "A192KW",
                                         "A256KW",
                                         "A128GCMKW",
                                         "A192GCMKW",
                                         "A256GCMKW"};
    if (sig_algs.count(alg))
        return JWK::Use::signature;
    if (enc_algs.count(alg))
        return JWK::Use::encryption;
    throw runtime_error("Cannot infer 'use' from unknown algorithm: '" + alg + "'");
}

void ensureKeyID(JWK &jwk)
{
    if (jwk.getKeyID().empty())
    {
        jwk.setKeyID(JWKThumbprint::compute(jwk).get());
    }
}

/// Return the required symmetric key size in bits for a given JWA algorithm.
/// AES variants encode the size directly in the name (e.g. A128KW → 128).
/// HMAC sizes match the hash output length per RFC 7518 §3.2 (HS256 → 256, etc.).
unsigned int keySizeFromAlg(string const &alg)
{
    if (alg == "A128KW" || alg == "A128GCMKW")
        return 128;
    if (alg == "A192KW" || alg == "A192GCMKW")
        return 192;
    if (alg == "A256KW" || alg == "A256GCMKW")
        return 256;
    if (alg == "HS256")
        return 256;
    if (alg == "HS384")
        return 384;
    if (alg == "HS512")
        return 512;
    throw runtime_error("Cannot determine key size for algorithm: '" + alg + "'");
}

}  // anonymous namespace

JWK::JWK(Impl &&impl)
{
    impl_ = make_unique<Impl>(std::move(impl));
}

JWK::~JWK() = default;

JWK::JWK(const JWK &other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWK &JWK::operator=(const JWK &other)
{
    if (this != &other)
    {
        impl_ = make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWK::JWK(JWK &&other) noexcept = default;
JWK &JWK::operator=(JWK &&other) noexcept = default;

JWK JWK::generateRSA(Use use, unsigned int bits, string const &alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::rsa, use) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::rsa, use);

    Impl impl(KeyType::rsa, use, final_alg);

    Private::BackEndFactory &factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = std::move(back_end->generateRSA(bits));

    JWK jwk(std::move(impl));
    ensureKeyID(jwk);

    return jwk;
}

JWK JWK::generateEC(Use use, string const &curve, string const &alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::ec, use, curve) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::ec, use);

    Impl impl(KeyType::ec, use, final_alg);

    Private::BackEndFactory &factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = std::move(back_end->generateEC(curve));

    JWK jwk(std::move(impl));
    ensureKeyID(jwk);

    return jwk;
}

JWK JWK::generateOct(Use use, int bits, string const &alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::oct, use) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::oct, use);

    Impl impl(KeyType::oct, use, final_alg);

    Private::BackEndFactory &factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = std::move(back_end->generateOct(bits));

    JWK jwk(std::move(impl));
    ensureKeyID(jwk);

    return jwk;
}

JWK JWK::generateOKP(Use use, unsigned int bits, string const &alg)
{
    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::okp, use) : alg;

    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::okp, use);

    if (0 == bits)
    {
        // Default to 25519-family keys unless caller requests larger curves.
        bits = 255;
    }

    Impl impl(KeyType::okp, use, final_alg);

    Private::BackEndFactory &factory(Private::BackEndFactory::get());
    auto back_end(factory.createBackEnd());
    impl.key_ = std::move(back_end->generateOkp(use, bits));

    JWK jwk(std::move(impl));
    ensureKeyID(jwk);

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
        auto rsa_key = dynamic_cast<Private::RSAKey *>(impl_->key_.get());
        auto n(rsa_key->getN());
        auto e(rsa_key->getE());

        if (!n.empty())
        {
            json_obj["n"] = Base64URL::encode(n);
        }
        if (!e.empty())
        {
            json_obj["e"] = Base64URL::encode(e);
        }

        if (include_private)
        {
            auto d(rsa_key->getD());
            auto p(rsa_key->getP());
            auto q(rsa_key->getQ());
            auto dp(rsa_key->getDp());
            auto dq(rsa_key->getDq());
            auto qi(rsa_key->getQi());

            // Only serialize RSA private fields when we have a complete CRT key.
            // Partial private material is not portable across backends/providers.
            bool const has_full_private =
                !d.empty() && !p.empty() && !q.empty() && !dp.empty() && !dq.empty() && !qi.empty();
            if (has_full_private)
            {
                json_obj["d"] = Base64URL::encode(d);
                json_obj["p"] = Base64URL::encode(p);
                json_obj["q"] = Base64URL::encode(q);
                json_obj["dp"] = Base64URL::encode(dp);
                json_obj["dq"] = Base64URL::encode(dq);
                json_obj["qi"] = Base64URL::encode(qi);
            }
        }
    }
    else if (impl_->key_type_ == KeyType::ec && impl_->key_)
    {
        auto ec_key = dynamic_cast<Private::ECKey *>(impl_->key_.get());
        json_obj["crv"] = ec_key->getCurveName();

        auto x(ec_key->getX());
        auto y(ec_key->getY());
        auto d(ec_key->getD());

        if (!x.empty())
        {
            json_obj["x"] = Base64URL::encode(x);
        }
        if (!y.empty())
        {
            json_obj["y"] = Base64URL::encode(y);
        }
        if (include_private && !d.empty())
        {
            json_obj["d"] = Base64URL::encode(d);
        }
    }
    else if (impl_->key_type_ == KeyType::okp && impl_->key_)
    {
#if defined(JOSE_USE_CNG)
        throw runtime_error("OKP keys are not supported with CNG backend -- use OpenSSL");
#else
        auto okp_key = dynamic_cast<Private::OKPKey *>(impl_->key_.get());
        if (okp_key == nullptr)
        {
            throw runtime_error("Internal error: OKP key type mismatch");
        }

        json_obj["crv"] = okp_key->getCurveName();

        auto x(okp_key->getX());
        if (!x.empty())
        {
            json_obj["x"] = Base64URL::encode(x);
        }

        if (include_private)
        {
            auto d(okp_key->getD());
            if (!d.empty())
            {
                json_obj["d"] = Base64URL::encode(d);
            }
        }
#endif
    }
    else if (impl_->key_type_ == KeyType::oct && impl_->key_ && include_private)
    {
        auto oct_key = dynamic_cast<Private::OctKey *>(impl_->key_.get());
        auto k(oct_key->getK());
        if (!k.empty())
        {
            json_obj["k"] = Base64URL::encode(k);
        }
    }
    return json_obj.dump();
}

JWK JWK::fromJSON(string const &json_str, bool ignore_private_if_present)
{
    json jwk_json = json::parse(json_str);

    if (!jwk_json.contains("kty"))
    {
        throw runtime_error("Missing kty field");
    }

    string kty = jwk_json["kty"].get<string>();
    if (kty != "RSA" && kty != "EC" && kty != "oct" && kty != "OKP")
    {
        throw runtime_error("Unsupported key type: " + kty);
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
    if (kty == "RSA")
        key_type = KeyType::rsa;
    else if (kty == "EC")
        key_type = KeyType::ec;
    else if (kty == "oct")
        key_type = KeyType::oct;
    else
        key_type = KeyType::okp;

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

    Private::BackEndFactory &factory(Private::BackEndFactory::get());
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
            auto n_bytes = Base64URL::decode(jwk_json["n"].get<string>());
            auto e_bytes = Base64URL::decode(jwk_json["e"].get<string>());
            auto d_bytes = !ignore_private_if_present && jwk_json.contains("d")
                               ? Base64URL::decode(jwk_json["d"].get<string>())
                               : vector<unsigned char>{};
            auto p_bytes = !ignore_private_if_present && jwk_json.contains("p")
                               ? Base64URL::decode(jwk_json["p"].get<string>())
                               : vector<unsigned char>{};
            auto q_bytes = !ignore_private_if_present && jwk_json.contains("q")
                               ? Base64URL::decode(jwk_json["q"].get<string>())
                               : vector<unsigned char>{};
            auto dp_bytes = !ignore_private_if_present && jwk_json.contains("dp")
                                ? Base64URL::decode(jwk_json["dp"].get<string>())
                                : vector<unsigned char>{};
            auto dq_bytes = !ignore_private_if_present && jwk_json.contains("dq")
                                ? Base64URL::decode(jwk_json["dq"].get<string>())
                                : vector<unsigned char>{};
            auto qi_bytes = !ignore_private_if_present && jwk_json.contains("qi")
                                ? Base64URL::decode(jwk_json["qi"].get<string>())
                                : vector<unsigned char>{};

            bool const has_d = !d_bytes.empty();
            bool const has_p = !p_bytes.empty();
            bool const has_q = !q_bytes.empty();
            bool const has_dp = !dp_bytes.empty();
            bool const has_dq = !dq_bytes.empty();
            bool const has_qi = !qi_bytes.empty();
            bool const has_any_crt = has_p || has_q || has_dp || has_dq || has_qi;
            bool const has_full_crt = has_p && has_q && has_dp && has_dq && has_qi;

            if (has_any_crt)
            {
                if (!has_d)
                {
                    throw runtime_error("Ill-formed RSA private key: parameter 'd' is required "
                                        "when CRT parameters are present");
                }
                if (!has_full_crt)
                {
                    throw runtime_error("Ill-formed RSA private key: if any of p, q, dp, dq, qi "
                                        "are present, all must be present");
                }
            }

            impl.key_ = std::move(back_end->generateRSA(n_bytes,
                                                        e_bytes,
                                                        d_bytes,
                                                        p_bytes,
                                                        q_bytes,
                                                        dp_bytes,
                                                        dq_bytes,
                                                        qi_bytes));
            break;
        }
        case KeyType::ec:
        {
            if (!jwk_json.contains("crv") || !jwk_json.contains("x") || !jwk_json.contains("y"))
            {
                throw runtime_error("Missing required EC parameters");
            }

            auto x_bytes = Base64URL::decode(jwk_json["x"].get<string>());
            auto y_bytes = Base64URL::decode(jwk_json["y"].get<string>());
            auto d_bytes = !ignore_private_if_present && jwk_json.contains("d")
                               ? Base64URL::decode(jwk_json["d"].get<string>())
                               : vector<unsigned char>{};

            impl.key_ = std::move(
                back_end->generateEC(jwk_json["crv"].get<string>(), x_bytes, y_bytes, d_bytes));
            break;
        }
        case KeyType::okp:
#if defined(JOSE_USE_CNG)
            throw runtime_error("OKP keys are not supported with CNG backend -- use OpenSSL");
#else
        {
            if (!jwk_json.contains("crv") || !jwk_json.contains("x"))
            {
                throw runtime_error("Missing required OKP parameters");
            }

            auto x_bytes = Base64URL::decode(jwk_json["x"].get<string>());
            auto d_bytes = !ignore_private_if_present && jwk_json.contains("d")
                               ? Base64URL::decode(jwk_json["d"].get<string>())
                               : vector<unsigned char>{};
            impl.key_ =
                std::move(back_end->generateOkp(jwk_json["crv"].get<string>(), x_bytes, d_bytes));
            break;
        }
#endif
        case KeyType::oct:
        {
            if (!ignore_private_if_present && !jwk_json.contains("k"))
            {
                throw runtime_error("Missing required 'k' parameter for symmetric key");
            }
            auto k_bytes = !ignore_private_if_present && jwk_json.contains("k")
                               ? Base64URL::decode(jwk_json["k"].get<string>())
                               : vector<unsigned char>{};
            impl.key_ = make_unique<Private::OctKey>(k_bytes);
            break;
        }
    }

    JWK jwk(std::move(impl));
    ensureKeyID(jwk);
    return jwk;
}

pair<optional<JWK>, bool>
JWK::fromJSON(string const &json, bool ignore_private_if_present, nothrow_t const &)
{
    try
    {
        return make_pair(make_optional<JWK>(JWK::fromJSON(json, ignore_private_if_present)), true);
    }
    catch (...)
    {
        return make_pair(nullopt, false);
    }
}

JWK::KeyType JWK::getKeyType() const
{
    return impl_->key_type_;
}

void JWK::setKeyID(string const &kid)
{
    impl_->kid_ = kid;
}

string JWK::getKeyID() const
{
    return impl_->kid_;
}

bool JWK::hasUse() const
{
    return impl_->has_use_;
}

JWK::Use JWK::getUse() const
{
    if (!impl_->has_use_)
    {
        throw runtime_error("Key use is not set");
    }
    return impl_->use_;
}

void JWK::setUse(Use use)
{
    impl_->use_ = use;
    impl_->has_use_ = true;
}

void JWK::setAlgorithm(string const &alg)
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
}

}  // namespace JOSE
}  // namespace Vlinder
