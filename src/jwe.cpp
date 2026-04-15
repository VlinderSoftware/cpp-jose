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
    return Base64URL::decode(key_json["k"].get<string>());
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

}  // anonymous namespace

struct JWE::Impl
{
    JWA::KeyEncryptionAlgorithm kea_ = JWA::KeyEncryptionAlgorithm::rsa_oaep;
    JWA::ContentEncryptionAlgorithm cea_ = JWA::ContentEncryptionAlgorithm::a256gcm;
    string kid_;
    string typ_;
    map<string, string> header_params_;
    // RFC 7516 compact serialization parts (set by encrypt() or fromCompact_())
    string header_b64_;
    vector<unsigned char> encrypted_key_;
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
    impl->encrypted_key_ = std::move(encrypted_key);
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
    impl->encrypted_key_ = std::move(*encrypted_key_opt);
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

    if (!header.contains("alg") || !header.at("alg").is_string())
        return makeError<JWE>("JWE fromJSON: protected header missing required 'alg' field");
    if (!header.contains("enc") || !header.at("enc").is_string())
        return makeError<JWE>("JWE fromJSON: protected header missing required 'enc' field");

    auto kea_opt = JWA::keyEncryptionAlgorithmFromString(header.at("alg").get<string>(), nothrow);
    if (!kea_opt)
        return makeError<JWE>("JWE fromJSON: unknown key encryption algorithm: " +
                              header.at("alg").get<string>());

    auto cea_opt =
        JWA::contentEncryptionAlgorithmFromString(header.at("enc").get<string>(), nothrow);
    if (!cea_opt)
        return makeError<JWE>("JWE fromJSON: unknown content encryption algorithm: " +
                              header.at("enc").get<string>());

    // encrypted_key: top-level for flattened, or inside recipients[0] for general
    string encrypted_key_b64;
    if (j.contains("encrypted_key") && j.at("encrypted_key").is_string())
    {
        encrypted_key_b64 = j.at("encrypted_key").get<string>();
    }
    else if (j.contains("recipients") && j.at("recipients").is_array() &&
             !j.at("recipients").empty())
    {
        auto const &r = j.at("recipients")[0];
        if (r.is_object() && r.contains("encrypted_key") && r.at("encrypted_key").is_string())
            encrypted_key_b64 = r.at("encrypted_key").get<string>();
    }

    auto encrypted_key_opt = Base64URL::decode(encrypted_key_b64, nothrow);
    if (!encrypted_key_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'encrypted_key'");

    auto iv_opt = Base64URL::decode(j.at("iv").get<string>(), nothrow);
    if (!iv_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'iv'");

    auto ciphertext_opt = Base64URL::decode(j.at("ciphertext").get<string>(), nothrow);
    if (!ciphertext_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'ciphertext'");

    auto auth_tag_opt = Base64URL::decode(j.at("tag").get<string>(), nothrow);
    if (!auth_tag_opt)
        return makeError<JWE>("JWE fromJSON: failed to base64url-decode 'tag'");

    auto impl = make_unique<Impl>();
    impl->kea_ = *kea_opt;
    impl->cea_ = *cea_opt;
    impl->header_b64_ = header_b64;
    impl->encrypted_key_ = std::move(*encrypted_key_opt);
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
    return impl_->header_b64_ + "." + Base64URL::encode(impl_->encrypted_key_) + "." +
           Base64URL::encode(impl_->iv_) + "." + Base64URL::encode(impl_->ciphertext_) + "." +
           Base64URL::encode(impl_->auth_tag_);
}

string JWE::toJSON() const
{
    json j = json::object();
    j["protected"] = impl_->header_b64_;
    j["encrypted_key"] = Base64URL::encode(impl_->encrypted_key_);
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
    json header = json::parse(header_str, nullptr, false);

    JWA::KeyEncryptionAlgorithm const kea = impl.kea_;
    JWA::ContentEncryptionAlgorithm const cea = impl.cea_;

    vector<unsigned char> cek;

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
        // RFC 7518 §4.6 — derive CEK from ephemeral public key in header
        if (!header.contains("epk"))
            throw runtime_error("JWE decrypt: ECDH-ES header missing 'epk'");
        JWK const ephemeral_key = JWK::fromJSON(header.at("epk").dump());
        vector<unsigned char> const empty_encrypted_key;
        try
        {
            cek = JWA::decryptKey(kea, key, empty_encrypted_key, {}, {}, ephemeral_key, cea);
        }
        catch (exception const &e)
        {
            throw runtime_error(string("JWE decrypt: ECDH-ES key agreement failed: ") + e.what());
        }
    }
    else
    {
        vector<unsigned char> kek_iv;
        vector<unsigned char> kek_tag;
        if (header.contains("iv") && header.at("iv").is_string())
            kek_iv = Base64URL::decode(header.at("iv").get<string>());
        if (header.contains("tag") && header.at("tag").is_string())
            kek_tag = Base64URL::decode(header.at("tag").get<string>());

        optional<vector<unsigned char>> const iv_arg =
            kek_iv.empty() ? optional<vector<unsigned char>>{} : kek_iv;
        optional<vector<unsigned char>> const tag_arg =
            kek_tag.empty() ? optional<vector<unsigned char>>{} : kek_tag;

        try
        {
            cek = JWA::decryptKey(kea, key, impl.encrypted_key_, iv_arg, tag_arg, {}, cea);
        }
        catch (exception const &e)
        {
            throw runtime_error(string("JWE decrypt: key decryption failed: ") + e.what());
        }
    }

    // AAD = ASCII(BASE64URL(JWE Protected Header)) — RFC 7516 §5.2 step 11
    vector<unsigned char> const aad(impl.header_b64_.begin(), impl.header_b64_.end());

    try
    {
        return JWA::decryptContent(cea, cek, impl.iv_, impl.ciphertext_, aad, impl.auth_tag_);
    }
    catch (exception const &e)
    {
        throw runtime_error(string("JWE decrypt: content decryption failed: ") + e.what());
    }
}

vector<unsigned char> decrypt(string const &compact, JWK const &key)
{
    return decrypt(JWE::fromCompact(compact), key);
}

}  // namespace JOSE
}  // namespace Vlinder
