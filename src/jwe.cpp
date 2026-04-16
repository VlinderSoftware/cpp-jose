#include "jwe.hpp"

#include <map>
#include <span>
#include <stdexcept>

#include "base64url.hpp"
#include "jwa.hpp"
#include "jwk.hpp"
#include "private/json_utils.hpp"
#include "private/result.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;
using Vlinder::JOSE::Private::makeError;
using Vlinder::JOSE::Private::makeOk;

namespace Vlinder {
namespace JOSE {

namespace {

vector<unsigned char> generateRandomBytes(size_t byte_count)
{
    if (byte_count == 0)
        return {};
    JWK random_key = JWK::generateOct(JWK::Use::encryption, static_cast<int>(byte_count * 8));
    json key_json = json::parse(random_key.toJSON(true));
    if (!key_json.contains("k"))
        throw runtime_error("Generated octet key is missing required JWK parameter 'k'");

    auto const decoded_key = Base64URL::decode(key_json.at("k").get<string>());
    if (decoded_key.size() != byte_count)
        throw runtime_error("Generated octet key has invalid length");

    return decoded_key;
}

size_t getKeySize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::a128gcm:
            return 16;
        case JWA::ContentEncryptionAlgorithm::a128cbc_hs256:
            return 32;
        case JWA::ContentEncryptionAlgorithm::a192gcm:
            return 24;
        case JWA::ContentEncryptionAlgorithm::a192cbc_hs384:
            return 48;
        case JWA::ContentEncryptionAlgorithm::a256gcm:
            return 32;
        case JWA::ContentEncryptionAlgorithm::a256cbc_hs512:
            return 64;
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

size_t getIVSize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::a128gcm:
        case JWA::ContentEncryptionAlgorithm::a192gcm:
        case JWA::ContentEncryptionAlgorithm::a256gcm:
            return 12;
        case JWA::ContentEncryptionAlgorithm::a128cbc_hs256:
        case JWA::ContentEncryptionAlgorithm::a192cbc_hs384:
        case JWA::ContentEncryptionAlgorithm::a256cbc_hs512:
            return 16;
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

/// Return true for algorithms that transmit a wrapped CEK in the JWE token
/// (RFC 7516 §5.1 step 5).  Returns false for @c dir and @c ecdh_es, where
/// the encrypted_key field MUST be absent / empty (RFC 7518 §4.5, §4.6).
bool requiresWrappedKey(JWA::KeyEncryptionAlgorithm kea)
{
    switch (kea)
    {
        case JWA::KeyEncryptionAlgorithm::dir:
        case JWA::KeyEncryptionAlgorithm::ecdh_es:
            return false;
        default:
            return true;
    }
}

}  // anonymous namespace

struct JWE::Impl
{
    /// One entry per recipient (RFC 7516 §7.2.1).
    struct Recipient
    {
        vector<unsigned char> encrypted_key;
        string header_json;  ///< per-recipient unprotected header JSON (may be empty)
    };

    JWA::KeyEncryptionAlgorithm kea_ = JWA::KeyEncryptionAlgorithm::rsa_oaep;
    JWA::ContentEncryptionAlgorithm cea_ = JWA::ContentEncryptionAlgorithm::a256gcm;
    string kid_;
    string typ_;
    map<string, string> header_params_;
    // RFC 7516 compact serialization parts (set by encrypt() or fromCompact_())
    string header_b64_;
    vector<Recipient> recipients_;  ///< one entry per recipient; never empty after construction
    vector<unsigned char> iv_;
    vector<unsigned char> ciphertext_;
    vector<unsigned char> auth_tag_;
};

JWE::~JWE() = default;

JWE::JWE(JWE const &other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWE &JWE::operator=(JWE const &other)
{
    if (this != &other)
        impl_ = make_unique<Impl>(*other.impl_);
    return *this;
}

JWE::JWE(JWE &&other) noexcept = default;
JWE &JWE::operator=(JWE &&other) noexcept = default;

JWE::JWE(unique_ptr<Impl> impl) : impl_(std::move(impl))
{
}

JWE EncryptAttorney::construct(JWA::KeyEncryptionAlgorithm kea,
                               JWA::ContentEncryptionAlgorithm cea,
                               string kid,
                               string typ,
                               map<string, string> header_params,
                               string header_b64,
                               vector<unsigned char> encrypted_key,
                               vector<unsigned char> iv,
                               vector<unsigned char> ciphertext,
                               vector<unsigned char> auth_tag)
{
    auto impl = make_unique<JWE::Impl>();
    impl->kea_ = kea;
    impl->cea_ = cea;
    impl->kid_ = std::move(kid);
    impl->typ_ = std::move(typ);
    impl->header_params_ = std::move(header_params);
    impl->header_b64_ = std::move(header_b64);
    JWE::Impl::Recipient r;
    r.encrypted_key = std::move(encrypted_key);
    impl->recipients_.push_back(std::move(r));
    impl->iv_ = std::move(iv);
    impl->ciphertext_ = std::move(ciphertext);
    impl->auth_tag_ = std::move(auth_tag);
    return JWE(std::move(impl));
}

pair<optional<JWE>, string> JWE::fromCompact_(string const &compact)
{
    // RFC 7516 §7.1: exact five dot-separated base64url parts
    vector<string> parts;
    parts.reserve(5);
    size_t start = 0;
    size_t pos;
    while ((pos = compact.find('.', start)) != string::npos)
    {
        parts.push_back(compact.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(compact.substr(start));

    if (parts.size() != 5)
        return makeError<JWE>("JWE fromCompact: expected 5 parts, got " + to_string(parts.size()));

    auto header_str_opt = Base64URL::decodeToString(parts[0], nothrow);
    if (!header_str_opt)
        return makeError<JWE>("JWE fromCompact: failed to base64url-decode protected header");

    json header = json::parse(*header_str_opt, nullptr, false);
    if (header.is_discarded())
        return makeError<JWE>("JWE fromCompact: protected header is not valid JSON");
    if (!header.is_object())
        return makeError<JWE>("JWE fromCompact: protected header is not a JSON object");

    if (!header.contains("alg") || !header.at("alg").is_string())
        return makeError<JWE>("JWE fromCompact: protected header missing required 'alg' field");
    if (!header.contains("enc") || !header.at("enc").is_string())
        return makeError<JWE>("JWE fromCompact: protected header missing required 'enc' field");

    auto kea_opt = JWA::keyEncryptionAlgorithmFromString(header.at("alg").get<string>(), nothrow);
    if (!kea_opt)
        return makeError<JWE>("JWE fromCompact: unknown key encryption algorithm: " +
                              header.at("alg").get<string>());

    auto cea_opt =
        JWA::contentEncryptionAlgorithmFromString(header.at("enc").get<string>(), nothrow);
    if (!cea_opt)
        return makeError<JWE>("JWE fromCompact: unknown content encryption algorithm: " +
                              header.at("enc").get<string>());

    auto encrypted_key_opt = Base64URL::decode(parts[1], nothrow);
    if (!encrypted_key_opt)
        return makeError<JWE>("JWE fromCompact: failed to base64url-decode encrypted_key");

    // RFC 7518 §4.5/§4.6: dir and ECDH-ES MUST have an empty encrypted_key part.
    // All key-wrapping algorithms MUST have a non-empty encrypted_key part.
    if (requiresWrappedKey(*kea_opt) && encrypted_key_opt->empty())
        return makeError<JWE>("JWE fromCompact: 'encrypted_key' must not be empty for alg '" +
                              header.at("alg").get<string>() + "'");
    if (!requiresWrappedKey(*kea_opt) && !encrypted_key_opt->empty())
        return makeError<JWE>("JWE fromCompact: 'encrypted_key' must be empty for alg '" +
                              header.at("alg").get<string>() + "' (RFC 7518 §4.5/§4.6)");

    auto iv_opt = Base64URL::decode(parts[2], nothrow);
    if (!iv_opt)
        return makeError<JWE>("JWE fromCompact: failed to base64url-decode iv");

    auto ciphertext_opt = Base64URL::decode(parts[3], nothrow);
    if (!ciphertext_opt)
        return makeError<JWE>("JWE fromCompact: failed to base64url-decode ciphertext");

    auto auth_tag_opt = Base64URL::decode(parts[4], nothrow);
    if (!auth_tag_opt)
        return makeError<JWE>("JWE fromCompact: failed to base64url-decode authentication_tag");

    auto impl = make_unique<Impl>();
    impl->kea_ = *kea_opt;
    impl->cea_ = *cea_opt;
    impl->header_b64_ = parts[0];
    Impl::Recipient r;
    r.encrypted_key = std::move(*encrypted_key_opt);
    impl->recipients_.push_back(std::move(r));
    impl->iv_ = std::move(*iv_opt);
    impl->ciphertext_ = std::move(*ciphertext_opt);
    impl->auth_tag_ = std::move(*auth_tag_opt);
    if (header.contains("kid") && header.at("kid").is_string())
        impl->kid_ = header.at("kid").get<string>();
    if (header.contains("typ") && header.at("typ").is_string())
        impl->typ_ = header.at("typ").get<string>();

    return makeOk<JWE>(JWE(std::move(impl)));
}

JWE JWE::fromCompact(string const &compact)
{
    auto [jwe_opt, jwe_err] = fromCompact_(compact);
    if (!jwe_opt)
        throw runtime_error(jwe_err);
    return std::move(*jwe_opt);
}

optional<JWE> JWE::fromCompact(string const &compact, nothrow_t const &) noexcept
{
    return fromCompact_(compact).first;
}

pair<optional<JWE>, string> JWE::fromJSON_(string const &json_str)
{
    json j = json::parse(json_str, nullptr, false);
    if (j.is_discarded())
        return makeError<JWE>("JWE fromJSON: invalid JSON");
    if (!j.is_object())
        return makeError<JWE>("JWE fromJSON: expected a JSON object");

    // RFC 7516 §7.2 flattened/general serialization — required fields
    if (!j.contains("protected") || !j.at("protected").is_string())
        return makeError<JWE>("JWE fromJSON: missing required 'protected' string");
    if (!j.contains("ciphertext") || !j.at("ciphertext").is_string())
        return makeError<JWE>("JWE fromJSON: missing required 'ciphertext' string");
    if (!j.contains("tag") || !j.at("tag").is_string())
        return makeError<JWE>("JWE fromJSON: missing required 'tag' string");
    if (!j.contains("iv") || !j.at("iv").is_string())
        return makeError<JWE>("JWE fromJSON: missing required 'iv' string");

    string const header_b64 = j.at("protected").get<string>();
    auto header_str_opt = Base64URL::decodeToString(header_b64, nothrow);
    if (!header_str_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'protected'");

    json header = json::parse(*header_str_opt, nullptr, false);
    if (header.is_discarded() || !header.is_object())
        return makeError<JWE>("JWE fromJSON: 'protected' is not a valid JSON object");

    string alg_value;
    if (header.contains("alg") && header.at("alg").is_string())
    {
        alg_value = header.at("alg").get<string>();
    }
    else if (j.contains("header") && j.at("header").is_object() && j.at("header").contains("alg") &&
             j.at("header").at("alg").is_string())
    {
        alg_value = j.at("header").at("alg").get<string>();
    }
    else if (j.contains("recipients") && j.at("recipients").is_array())
    {
        for (auto const &recipient : j.at("recipients"))
        {
            if (!recipient.is_object() || !recipient.contains("header") ||
                !recipient.at("header").is_object() || !recipient.at("header").contains("alg") ||
                !recipient.at("header").at("alg").is_string())
            {
                continue;
            }

            alg_value = recipient.at("header").at("alg").get<string>();
            break;
        }
    }

    if (alg_value.empty())
        return makeError<JWE>("JWE fromJSON: missing required 'alg' field");
    if (!header.contains("enc") || !header.at("enc").is_string())
        return makeError<JWE>("JWE fromJSON: protected header missing required 'enc' field");

    auto kea_opt = JWA::keyEncryptionAlgorithmFromString(alg_value, nothrow);
    if (!kea_opt)
        return makeError<JWE>("JWE fromJSON: unknown key encryption algorithm: " + alg_value);

    auto cea_opt =
        JWA::contentEncryptionAlgorithmFromString(header.at("enc").get<string>(), nothrow);
    if (!cea_opt)
        return makeError<JWE>("JWE fromJSON: unknown content encryption algorithm: " +
                              header.at("enc").get<string>());

    auto impl = make_unique<Impl>();
    impl->kea_ = *kea_opt;
    impl->cea_ = *cea_opt;
    impl->header_b64_ = header_b64;

    // RFC 7516 §7.2: resolve recipients.
    // Flattened serialisation: top-level "encrypted_key" (and optional "header").
    // General serialisation: "recipients" array, each entry with "encrypted_key" and optional
    // "header".
    if (j.contains("encrypted_key") && j.at("encrypted_key").is_string())
    {
        auto ek_opt = Base64URL::decode(j.at("encrypted_key").get<string>(), nothrow);
        if (!ek_opt)
            return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'encrypted_key'");
        if (ek_opt->empty() && requiresWrappedKey(*kea_opt))
            return makeError<JWE>("JWE fromJSON: 'encrypted_key' must not be empty for alg '" +
                                  header.at("alg").get<string>() + "'");
        if (!ek_opt->empty() && !requiresWrappedKey(*kea_opt))
            return makeError<JWE>("JWE fromJSON: 'encrypted_key' must be empty or absent for alg '" +
                                  header.at("alg").get<string>() + "'");
        Impl::Recipient r;
        r.encrypted_key = std::move(*ek_opt);
        if (j.contains("header") && j.at("header").is_object())
            r.header_json = j.at("header").dump();
        impl->recipients_.push_back(std::move(r));
    }
    else if (j.contains("recipients") && j.at("recipients").is_array() &&
             !j.at("recipients").empty())
    {
        // General serialisation — parse every recipient (not just [0]).
        for (auto const &rec : j.at("recipients"))
        {
            if (!rec.is_object())
                return makeError<JWE>("JWE fromJSON: each recipient must be a JSON object");

            // Effective per-recipient alg: prefer the per-recipient header's "alg" if present,
            // otherwise fall back to the protected header's value already parsed into *kea_opt.
            JWA::KeyEncryptionAlgorithm rec_kea = *kea_opt;
            if (rec.contains("header") && rec.at("header").is_object() &&
                rec.at("header").contains("alg") && rec.at("header").at("alg").is_string())
            {
                auto rec_kea_opt =
                    JWA::keyEncryptionAlgorithmFromString(rec.at("header").at("alg").get<string>(),
                                                          nothrow);
                if (rec_kea_opt)
                    rec_kea = *rec_kea_opt;
            }

            bool const has_ek =
                rec.contains("encrypted_key") && rec.at("encrypted_key").is_string();
            if (!has_ek && requiresWrappedKey(rec_kea))
                return makeError<JWE>(
                    "JWE fromJSON: recipient is missing 'encrypted_key' for alg '" +
                    JWA::toString(rec_kea) + "'");

            string const ek_b64 = has_ek ? rec.at("encrypted_key").get<string>() : string{};
            auto ek_opt = Base64URL::decode(ek_b64, nothrow);
            if (!ek_opt)
                return makeError<JWE>(
                    "JWE fromJSON: failed to base64url-decode recipient 'encrypted_key'");
            if (ek_opt->empty() && requiresWrappedKey(rec_kea))
                return makeError<JWE>(
                    "JWE fromJSON: recipient 'encrypted_key' must not be empty for alg '" +
                    JWA::toString(rec_kea) + "'");
            if (!requiresWrappedKey(rec_kea) && !ek_opt->empty())
                return makeError<JWE>(
                    "JWE fromJSON: recipient 'encrypted_key' must be empty for alg '" +
                    JWA::toString(rec_kea) + "'");
            Impl::Recipient r;
            r.encrypted_key = std::move(*ek_opt);
            if (rec.contains("header") && rec.at("header").is_object())
                r.header_json = rec.at("header").dump();
            impl->recipients_.push_back(std::move(r));
        }
    }
    else if (!requiresWrappedKey(*kea_opt))
    {
        // dir / ECDH-ES: no encrypted_key field — this is correct per RFC 7518 §4.5, §4.6.
        impl->recipients_.push_back(Impl::Recipient{});
    }
    else
    {
        return makeError<JWE>("JWE fromJSON: missing 'encrypted_key' for alg '" +
                              header.at("alg").get<string>() + "'");
    }

    auto iv_opt = Base64URL::decode(j.at("iv").get<string>(), nothrow);
    if (!iv_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'iv'");

    auto ciphertext_opt = Base64URL::decode(j.at("ciphertext").get<string>(), nothrow);
    if (!ciphertext_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'ciphertext'");

    auto auth_tag_opt = Base64URL::decode(j.at("tag").get<string>(), nothrow);
    if (!auth_tag_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'tag'");

    impl->iv_ = std::move(*iv_opt);
    impl->ciphertext_ = std::move(*ciphertext_opt);
    impl->auth_tag_ = std::move(*auth_tag_opt);
    if (header.contains("kid") && header.at("kid").is_string())
        impl->kid_ = header.at("kid").get<string>();
    if (header.contains("typ") && header.at("typ").is_string())
        impl->typ_ = header.at("typ").get<string>();

    return makeOk<JWE>(JWE(std::move(impl)));
}

JWE JWE::fromJSON(string const &json_str)
{
    auto [jwe_opt, jwe_err] = fromJSON_(json_str);
    if (!jwe_opt)
        throw runtime_error(jwe_err);
    return std::move(*jwe_opt);
}

optional<JWE> JWE::fromJSON(string const &json_str, nothrow_t const &) noexcept
{
    return fromJSON_(json_str).first;
}

string JWE::toCompact() const
{
    if (impl_->recipients_.size() != 1)
        throw runtime_error("JWE toCompact: compact serialisation requires exactly one recipient; "
                            "use toJSON() for multi-recipient tokens");
    return impl_->header_b64_ + "." + Base64URL::encode(impl_->recipients_[0].encrypted_key) + "." +
           Base64URL::encode(impl_->iv_) + "." + Base64URL::encode(impl_->ciphertext_) + "." +
           Base64URL::encode(impl_->auth_tag_);
}

string JWE::toJSON() const
{
    json j = json::object();
    j["protected"] = impl_->header_b64_;

    bool const single_anon =
        impl_->recipients_.size() == 1 && impl_->recipients_[0].header_json.empty();
    if (single_anon)
    {
        // RFC 7516 §7.2 flattened serialisation (backward-compatible default)
        j["encrypted_key"] = Base64URL::encode(impl_->recipients_[0].encrypted_key);
    }
    else
    {
        // RFC 7516 §7.2.1 general serialisation — emit all recipients
        json recipients_arr = json::array();
        for (auto const &recipient : impl_->recipients_)
        {
            json r = json::object();
            r["encrypted_key"] = Base64URL::encode(recipient.encrypted_key);
            if (!recipient.header_json.empty())
            {
                json rh = json::parse(recipient.header_json, nullptr, false);
                if (!rh.is_discarded() && rh.is_object())
                    r["header"] = rh;
            }
            recipients_arr.push_back(r);
        }
        j["recipients"] = recipients_arr;
    }

    j["iv"] = Base64URL::encode(impl_->iv_);
    j["ciphertext"] = Base64URL::encode(impl_->ciphertext_);
    j["tag"] = Base64URL::encode(impl_->auth_tag_);
    return j.dump();
}

JWA::KeyEncryptionAlgorithm JWE::getKeyEncryptionAlgorithm() const
{
    return impl_->kea_;
}

JWA::ContentEncryptionAlgorithm JWE::getContentEncryptionAlgorithm() const
{
    return impl_->cea_;
}

string JWE::getKeyID() const
{
    return impl_->kid_;
}

string JWE::getType() const
{
    return impl_->typ_;
}

string JWE::getHeader() const
{
    return Base64URL::decodeToString(impl_->header_b64_);
}

// ── canonical encrypt() ───────────────────────────────────────────────────────

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            string const &type,
            map<string, string> const &header_params,
            span<unsigned char const> const &payload)
{
    // Validate reserved JWE header parameter names — RFC 7516 §4
    static constexpr char const *reserved[] = {
        "alg", "enc", "zip",  "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256",
        "typ", "cty", "crit", "epk", "apu", "apv", "iv",  "tag", "p2s", "p2c"};
    for (auto const &param : header_params)
    {
        for (auto const *name : reserved)
        {
            if (param.first == name)
                throw invalid_argument(
                    string("header_params must not contain reserved JWE header parameter '") +
                    name + "'");
        }
    }

    string const kid = key.getKeyID();

    vector<unsigned char> cek;
    vector<unsigned char> encrypted_key;
    vector<unsigned char> kek_iv;
    vector<unsigned char> kek_tag;
    optional<JWK> ephemeral_key;

    if (kea == JWA::KeyEncryptionAlgorithm::dir)
    {
        // RFC 7518 §4.5 — direct encryption: key material is the CEK
        json key_json = json::parse(key.toJSON(true));
        if (!key_json.contains("kty") || !key_json.at("kty").is_string() ||
            key_json.at("kty").get<string>() != "oct")
            throw runtime_error("JWE encrypt: direct encryption requires an oct JWK");
        if (!key_json.contains("k") || !key_json.at("k").is_string())
            throw runtime_error("JWE encrypt: oct JWK missing required 'k' field");
        cek = Base64URL::decode(key_json.at("k").get<string>());
        // encrypted_key stays empty
    }
    else if (kea == JWA::KeyEncryptionAlgorithm::ecdh_es)
    {
        // RFC 7518 §4.6 — ECDH-ES: derive CEK via key agreement; no encrypted_key
        string crv = "P-256";
        try
        {
            json rj = json::parse(key.toJSON(false));
            if (rj.contains("crv") && rj.at("crv").is_string())
                crv = rj.at("crv").get<string>();
        }
        catch (...)
        {
        }
        ephemeral_key = JWK::generateEC(JWK::Use::encryption, crv);
        size_t const cek_size = getKeySize(cea);
        vector<unsigned char> const dummy_cek(cek_size);
        try
        {
            cek = JWA::encryptKey(kea, key, dummy_cek, {}, {}, ephemeral_key, cea);
        }
        catch (exception const &e)
        {
            throw runtime_error(string("JWE encrypt: ECDH-ES key agreement failed: ") + e.what());
        }
        // encrypted_key stays empty
    }
    else
    {
        // All other algorithms: generate random CEK and wrap it
        size_t const cek_size = getKeySize(cea);
        cek = generateRandomBytes(cek_size);

        bool const is_gcmkw = (kea == JWA::KeyEncryptionAlgorithm::a128gcmkw ||
                               kea == JWA::KeyEncryptionAlgorithm::a192gcmkw ||
                               kea == JWA::KeyEncryptionAlgorithm::a256gcmkw);
        try
        {
            if (is_gcmkw)
            {
                // RFC 7518 §4.7 — backend packs [IV(12)‖ciphertext‖Tag(16)]
                auto raw = JWA::encryptKey(kea, key, cek, {}, {}, {}, cea);
                constexpr size_t kGcmIvSize = 12;
                constexpr size_t kGcmTagSize = 16;
                if (raw.size() < kGcmIvSize + kGcmTagSize)
                    throw runtime_error("AES-GCM key wrap returned insufficient data");
                kek_iv.assign(raw.begin(), raw.begin() + kGcmIvSize);
                kek_tag.assign(raw.end() - kGcmTagSize, raw.end());
                encrypted_key.assign(raw.begin() + kGcmIvSize, raw.end() - kGcmTagSize);
            }
            else
            {
                encrypted_key = JWA::encryptKey(kea, key, cek, {}, {}, {}, cea);
            }
        }
        catch (exception const &e)
        {
            throw runtime_error(string("JWE encrypt: key encryption failed: ") + e.what());
        }
    }

    // Build the protected header
    json header = json::object();
    header["alg"] = JWA::toString(kea);
    header["enc"] = JWA::toString(cea);
    if (!kid.empty())
        header["kid"] = kid;
    if (!type.empty())
        header["typ"] = type;
    if (kea == JWA::KeyEncryptionAlgorithm::ecdh_es && ephemeral_key)
        header["epk"] = json::parse(ephemeral_key->toJSON(false));
    if (!kek_iv.empty())
        header["iv"] = Base64URL::encode(kek_iv);
    if (!kek_tag.empty())
        header["tag"] = Base64URL::encode(kek_tag);
    for (auto const &param : header_params)
        header[param.first] = param.second;

    string const header_b64 = Base64URL::encode(header.dump());

    // Random IV
    vector<unsigned char> iv = generateRandomBytes(getIVSize(cea));

    // AAD = ASCII(BASE64URL(JWE Protected Header)) — RFC 7516 §5.1 step 14
    vector<unsigned char> const aad(header_b64.begin(), header_b64.end());

    vector<unsigned char> const plaintext_bytes(payload.begin(), payload.end());
    vector<unsigned char> ciphertext;
    vector<unsigned char> auth_tag;
    try
    {
        auto [ct, at] = JWA::encryptContent(cea, cek, iv, plaintext_bytes, aad);
        ciphertext = std::move(ct);
        auth_tag = std::move(at);
    }
    catch (exception const &e)
    {
        throw runtime_error(string("JWE encrypt: content encryption failed: ") + e.what());
    }

    return EncryptAttorney::construct(kea,
                                      cea,
                                      kid,
                                      type,
                                      header_params,
                                      header_b64,
                                      std::move(encrypted_key),
                                      std::move(iv),
                                      std::move(ciphertext),
                                      std::move(auth_tag));
}

// ── encrypt() convenience overloads ──────────────────────────────────────────

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            span<unsigned char const> const &payload)
{
    return encrypt(key, kea, cea, "", {}, payload);
}

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            string const &type,
            span<unsigned char const> const &payload)
{
    return encrypt(key, kea, cea, type, {}, payload);
}

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            string const &type,
            string const &payload)
{
    return encrypt(
        key,
        kea,
        cea,
        type,
        {},
        span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                  payload.size()));
}

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            string const &type,
            map<string, string> const &header_params,
            string const &payload)
{
    return encrypt(
        key,
        kea,
        cea,
        type,
        header_params,
        span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                  payload.size()));
}

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            vector<unsigned char> const &payload)
{
    return encrypt(key, kea, cea, "", {}, span<unsigned char const>(payload));
}

JWE encrypt(JWK const &key,
            JWA::KeyEncryptionAlgorithm kea,
            JWA::ContentEncryptionAlgorithm cea,
            string const &payload)
{
    return encrypt(
        key,
        kea,
        cea,
        "",
        {},
        span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                  payload.size()));
}

// ── decrypt() ────────────────────────────────────────────────────────────────

vector<unsigned char> decrypt(JWE const &jwe, JWK const &key)
{
    JWE::Impl const &impl = *jwe.impl_;
    string const header_str = Base64URL::decodeToString(impl.header_b64_);
    json const protected_header = json::parse(header_str, nullptr, false);

    JWA::ContentEncryptionAlgorithm const cea = impl.cea_;

    // AAD = ASCII(BASE64URL(JWE Protected Header)) — RFC 7516 §5.2 step 11
    vector<unsigned char> const aad(impl.header_b64_.begin(), impl.header_b64_.end());

    string last_error;
    for (auto const &recipient : impl.recipients_)
    {
        // RFC 7516 §5.2 step 6: effective header = protected ∪ per-recipient header
        // (per-recipient takes precedence for fields that appear in both).
        json effective_header = protected_header;
        if (!recipient.header_json.empty())
        {
            json const rh = json::parse(recipient.header_json, nullptr, false);
            if (!rh.is_discarded() && rh.is_object())
                for (auto const &[k, v] : rh.items())
                    effective_header[k] = v;
        }

        // Resolve kea from the effective header's "alg".
        JWA::KeyEncryptionAlgorithm kea = impl.kea_;
        if (effective_header.contains("alg") && effective_header.at("alg").is_string())
        {
            auto kea_opt =
                JWA::keyEncryptionAlgorithmFromString(effective_header.at("alg").get<string>(),
                                                      nothrow);
            if (kea_opt)
                kea = *kea_opt;
        }

        vector<unsigned char> cek;
        try
        {
            if (kea == JWA::KeyEncryptionAlgorithm::dir)
            {
                // RFC 7518 §4.5 — direct encryption
                json key_json = json::parse(key.toJSON(true));
                if (!key_json.contains("kty") || !key_json.at("kty").is_string() ||
                    key_json.at("kty").get<string>() != "oct")
                    throw runtime_error("JWE decrypt: direct encryption requires an oct JWK");
                if (!key_json.contains("k") || !key_json.at("k").is_string())
                    throw runtime_error("JWE decrypt: oct JWK missing required 'k' field");
                cek = Base64URL::decode(key_json.at("k").get<string>());
            }
            else if (kea == JWA::KeyEncryptionAlgorithm::ecdh_es)
            {
                // RFC 7518 §4.6 — ephemeral public key may be in per-recipient or protected header
                if (!effective_header.contains("epk"))
                    throw runtime_error("JWE decrypt: ECDH-ES header missing 'epk'");
                JWK const ephemeral_key = JWK::fromJSON(effective_header.at("epk").dump());
                try
                {
                    cek = JWA::decryptKey(kea, key, {}, {}, {}, ephemeral_key, cea);
                }
                catch (exception const &e)
                {
                    throw runtime_error(string("JWE decrypt: ECDH-ES key agreement failed: ") +
                                        e.what());
                }
            }
            else
            {
                vector<unsigned char> kek_iv;
                vector<unsigned char> kek_tag;
                if (effective_header.contains("iv") && effective_header.at("iv").is_string())
                    kek_iv = Base64URL::decode(effective_header.at("iv").get<string>());
                if (effective_header.contains("tag") && effective_header.at("tag").is_string())
                    kek_tag = Base64URL::decode(effective_header.at("tag").get<string>());

                optional<vector<unsigned char>> const iv_arg =
                    kek_iv.empty() ? optional<vector<unsigned char>>{} : kek_iv;
                optional<vector<unsigned char>> const tag_arg =
                    kek_tag.empty() ? optional<vector<unsigned char>>{} : kek_tag;

                try
                {
                    cek = JWA::decryptKey(kea,
                                          key,
                                          recipient.encrypted_key,
                                          iv_arg,
                                          tag_arg,
                                          {},
                                          cea);
                }
                catch (exception const &e)
                {
                    throw runtime_error(string("JWE decrypt: key decryption failed: ") + e.what());
                }
            }
        }
        catch (exception const &e)
        {
            last_error = e.what();
            continue;  // try the next recipient
        }

        // CEK obtained — decrypt content.
        try
        {
            return JWA::decryptContent(cea, cek, impl.iv_, impl.ciphertext_, aad, impl.auth_tag_);
        }
        catch (exception const &e)
        {
            throw runtime_error(string("JWE decrypt: content decryption failed: ") + e.what());
        }
    }

    throw runtime_error(string("JWE decrypt: no recipient key matched: ") + last_error);
}

vector<unsigned char> decrypt(string const &compact, JWK const &key)
{
    return decrypt(JWE::fromCompact(compact), key);
}

}  // namespace JOSE
}  // namespace Vlinder
