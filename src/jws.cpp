#include "jws.hpp"

#include <map>
#include <mutex>
#include <stdexcept>

#include "base64url.hpp"
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
              []()
              {
                  Private::BackEndFactory &factory(Private::BackEndFactory::get());
                  back_end = std::move(factory.createBackEnd());
              });

    return *back_end;
}
}  // namespace

struct JWS::Impl
{
    struct SignatureEntry
    {
        JWA::SignatureAlgorithm algorithm_ = JWA::SignatureAlgorithm::rs256;
        string kid_;
        string typ_;
        map<string, string> header_params_;
        string header_b64_;
        vector<unsigned char> signature_;
    };

    Impl() = default;

    /// Single-signature constructor — used by sign() and fromCompact().
    Impl(vector<unsigned char> const &payload,
         JWA::SignatureAlgorithm algorithm,
         string const &kid,
         string const &typ,
         map<string, string> const &header_params,
         string const &header_b64,
         string const &payload_b64,
         vector<unsigned char> const &signature)
        : payload_(payload), payload_b64_(payload_b64)
    {
        signatures_.push_back({algorithm, kid, typ, header_params, header_b64, signature});
    }

    /// Multi-signature constructor — used by fromJSON() for general serialization.
    Impl(vector<unsigned char> const &payload,
         string const &payload_b64,
         vector<SignatureEntry> signatures)
        : payload_(payload), payload_b64_(payload_b64), signatures_(std::move(signatures))
    {
    }

    vector<unsigned char> payload_;
    string payload_b64_;
    vector<SignatureEntry> signatures_;
};

JWS::~JWS() = default;

JWS::JWS(JWS &&other) noexcept = default;

JWS &JWS::operator=(JWS &&other) noexcept = default;

JWS SignAttorney::construct(vector<unsigned char> payload,
                            JWA::SignatureAlgorithm alg,
                            string kid,
                            string typ,
                            map<string, string> header_params,
                            string header_b64,
                            string payload_b64,
                            vector<unsigned char> signature)
{
    auto impl = make_unique<JWS::Impl>(std::move(payload),
                                       alg,
                                       std::move(kid),
                                       std::move(typ),
                                       std::move(header_params),
                                       std::move(header_b64),
                                       std::move(payload_b64),
                                       std::move(signature));
    return JWS(std::move(impl));
}

JWS::JWS(const JWS &other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWS &JWS::operator=(const JWS &other)
{
    if (this != &other)
    {
        impl_ = make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWS &JWS::swap(JWS &other) noexcept
{
    using std::swap;
    swap(impl_, other.impl_);
    return *this;
}

vector<unsigned char> JWS::getPayload() const
{
    return impl_->payload_;
}

string JWS::toCompact() const
{
    if (impl_->signatures_.size() != 1)
    {
        throw runtime_error(
            "toCompact() requires exactly one signature; this JWS has " +
            to_string(impl_->signatures_.size()));
    }
    auto const &sig = impl_->signatures_[0];
    return sig.header_b64_ + "." + impl_->payload_b64_ + "." +
           Base64URL::encode(sig.signature_);
}

string JWS::toJSON(bool flattened) const
{
    if (flattened)
    {
        if (impl_->signatures_.size() != 1)
        {
            throw runtime_error(
                "toJSON(flattened) requires exactly one signature; this JWS has " +
                to_string(impl_->signatures_.size()));
        }
        auto const &sig = impl_->signatures_[0];
        json j = json::object();
        j["payload"] = impl_->payload_b64_;
        j["protected"] = sig.header_b64_;
        j["signature"] = Base64URL::encode(sig.signature_);
        return j.dump();
    }
    // General serialization — supports multiple signatures (RFC 7515 §7.2)
    json sigs_arr = json::array();
    for (auto const &sig : impl_->signatures_)
    {
        json sig_obj = json::object();
        sig_obj["protected"] = sig.header_b64_;
        sig_obj["signature"] = Base64URL::encode(sig.signature_);
        sigs_arr.push_back(sig_obj);
    }
    json j = json::object();
    j["payload"] = impl_->payload_b64_;
    j["signatures"] = sigs_arr;
    return j.dump();
}

JWS JWS::fromCompact(string const &compact)
{
    auto const dot1 = compact.find('.');
    if (dot1 == string::npos)
    {
        throw runtime_error("Invalid JWS compact serialization: missing first '.'");
    }
    auto const dot2 = compact.find('.', dot1 + 1);
    if (dot2 == string::npos)
    {
        throw runtime_error("Invalid JWS compact serialization: missing second '.'");
    }

    string const header_b64 = compact.substr(0, dot1);
    string const payload_b64 = compact.substr(dot1 + 1, dot2 - dot1 - 1);
    string const sig_b64 = compact.substr(dot2 + 1);

    json header = json::parse(Base64URL::decodeToString(header_b64));

    string alg_str = header.value("alg", "");
    JWA::SignatureAlgorithm alg = JWA::signatureAlgorithmFromString(alg_str);
    string kid = header.value("kid", "");
    string typ = header.value("typ", "");

    map<string, string> header_params;
    for (auto const &[k, v] : header.items())
    {
        if (k != "alg" && k != "kid" && k != "typ" && v.is_string())
        {
            header_params[k] = v.get<string>();
        }
    }

    auto payload_bytes = Base64URL::decode(payload_b64);
    auto signature = Base64URL::decode(sig_b64);

    Impl impl(payload_bytes, alg, kid, typ, header_params, header_b64, payload_b64, signature);
    return JWS(make_unique<Impl>(std::move(impl)));
}

optional<JWS> JWS::fromCompact(string const &compact, nothrow_t const &) noexcept
{
    try
    {
        return fromCompact(compact);
    }
    catch (...)
    {
        return nullopt;
    }
}

JWS JWS::fromJSON(string const &json_str)
{
    json const j = json::parse(json_str);

    auto const parse_sig_entry = [](string const &hdr_b64, string const &sig_b64) -> Impl::SignatureEntry
    {
        json header = json::parse(Base64URL::decodeToString(hdr_b64));
        string const alg_str = header.value("alg", "");
        JWA::SignatureAlgorithm alg = JWA::signatureAlgorithmFromString(alg_str);
        string const kid = header.value("kid", "");
        string const typ = header.value("typ", "");
        map<string, string> header_params;
        for (auto const &[k, v] : header.items())
        {
            if (k != "alg" && k != "kid" && k != "typ" && v.is_string())
            {
                header_params[k] = v.get<string>();
            }
        }
        return {alg, kid, typ, header_params, hdr_b64, Base64URL::decode(sig_b64)};
    };

    string payload_b64;
    vector<Impl::SignatureEntry> entries;

    if (j.contains("signatures"))
    {
        // General JWS JSON serialization (RFC 7515 §7.2)
        payload_b64 = j.at("payload").get<string>();
        auto const &sigs = j.at("signatures");
        if (sigs.empty())
        {
            throw runtime_error("JWS JSON has no signatures");
        }
        for (auto const &entry : sigs)
        {
            entries.push_back(parse_sig_entry(
                entry.at("protected").get<string>(),
                entry.at("signature").get<string>()));
        }
    }
    else
    {
        // Flattened JWS JSON serialization (RFC 7515 §7.2.2)
        payload_b64 = j.at("payload").get<string>();
        entries.push_back(parse_sig_entry(
            j.at("protected").get<string>(),
            j.at("signature").get<string>()));
    }

    auto payload_bytes = Base64URL::decode(payload_b64);
    return JWS(make_unique<Impl>(payload_bytes, payload_b64, std::move(entries)));
}

optional<JWS> JWS::fromJSON(string const &json_str, nothrow_t const &) noexcept
{
    try
    {
        return fromJSON(json_str);
    }
    catch (...)
    {
        return nullopt;
    }
}

optional<JWS> JWS::tryLoad(string const &input) noexcept
{
    auto jws = fromCompact(input, nothrow);
    if (jws.has_value())
    {
        return jws;
    }
    return fromJSON(input, nothrow);
}

JWS::JWS(unique_ptr<Impl> impl) : impl_(std::move(impl))
{
}

namespace {
bool isCompatibleWithKey(JWA::SignatureAlgorithm alg, JWK const &key)
{
    switch (alg)
    {
        case JWA::SignatureAlgorithm::hs256:
        case JWA::SignatureAlgorithm::hs384:
        case JWA::SignatureAlgorithm::hs512:
            return key.getKeyType() == JWK::KeyType::oct;
        case JWA::SignatureAlgorithm::rs256:
        case JWA::SignatureAlgorithm::rs384:
        case JWA::SignatureAlgorithm::rs512:
        case JWA::SignatureAlgorithm::ps256:
        case JWA::SignatureAlgorithm::ps384:
        case JWA::SignatureAlgorithm::ps512:
            return key.getKeyType() == JWK::KeyType::rsa;
        case JWA::SignatureAlgorithm::es256:
        case JWA::SignatureAlgorithm::es384:
        case JWA::SignatureAlgorithm::es512:
            return key.getKeyType() == JWK::KeyType::ec;
        case JWA::SignatureAlgorithm::none:
            return false;  // alg:none is never acceptable for verification (RFC 7515 §8.4)
    }
    return false;
}

bool kidMatches(string const &sig_kid, JWK const &key)
{
    string const key_kid = key.getKeyID();
    // If either kid is empty, do not filter by kid.
    if (sig_kid.empty() || key_kid.empty())
        return true;
    return sig_kid == key_kid;
}
}  // namespace

bool verify(JWS const &jws, JWK const &key)
{
    auto const &impl = *jws.impl_;
    bool found_applicable = false;
    for (auto const &sig : impl.signatures_)
    {
        // Skip signatures whose algorithm is incompatible with this key type,
        // or whose kid does not match the key's kid (when both are non-empty).
        if (!isCompatibleWithKey(sig.algorithm_, key) || !kidMatches(sig.kid_, key))
        {
            continue;
        }
        found_applicable = true;
        string const signing_input = sig.header_b64_ + "." + impl.payload_b64_;
        vector<unsigned char> const signing_input_bytes(signing_input.begin(), signing_input.end());
        // Any compatible signature that fails to verify causes the whole check to fail.
        if (!getBackEnd().verify(sig.algorithm_, key, signing_input_bytes, sig.signature_))
        {
            return false;
        }
    }
    // If no signature was applicable to this key, verification fails.
    return found_applicable;
}

JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::span<char const> const &payload)
{
    return sign(
        key,
        alg,
        "",
        {},
        std::span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                       payload.size()));
}

JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::span<unsigned char const> const &payload)
{
    return sign(key, alg, "", {}, payload);
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::span<char const> const &payload)
{
    return sign(
        key,
        alg,
        type,
        {},
        std::span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                       payload.size()));
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::span<unsigned char const> const &payload)
{
    return sign(key, alg, type, {}, payload);
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::span<char const> const &payload)
{
    return sign(
        key,
        alg,
        type,
        header_params,
        std::span<unsigned char const>(reinterpret_cast<unsigned char const *>(payload.data()),
                                       payload.size()));
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::span<unsigned char const> const &payload)
{
    // Check that the key is suitable for signing with the specified algorithm
    if (!key.hasUse() || key.getUse() != JWK::Use::signature)
    {
        throw std::invalid_argument("Key use must be 'signature' for signing");
    }

    // Reject the JOSE header parameter names that are set explicitly by sign().
    // header_params may contain other JOSE header members, but it must not
    // override alg, kid, or typ because that would create an inconsistent JWS
    // whose protected header does not match the signing inputs chosen here.
    static constexpr char const *reserved[] = {"alg", "kid", "typ"};
    for (auto const &param : header_params)
    {
        for (auto const *name : reserved)
        {
            if (param.first == name)
            {
                throw std::invalid_argument(
                    string("header_params must not contain reserved JOSE header parameter '") +
                    name + "'");
            }
        }
    }

    auto const kid = key.getKeyID();

    // Build JOSE header
    json header = json::object();
    header["alg"] = JWA::toString(alg);
    if (!kid.empty())
    {
        header["kid"] = kid;
    }
    if (!type.empty())
    {
        header["typ"] = type;
    }
    for (auto const &param : header_params)
    {
        header[param.first] = param.second;
    }

    // Base64URL encode header and payload (RFC 7515 signing input)
    string const header_b64 = Base64URL::encode(header.dump());
    string const payload_b64 = Base64URL::encode(payload);

    // Signing input: BASE64URL(header) || '.' || BASE64URL(payload)
    string const signing_input = header_b64 + "." + payload_b64;

    vector<unsigned char> signature;
    if (alg != JWA::SignatureAlgorithm::none)
    {
        auto const signing_span =
            span<unsigned char const>(reinterpret_cast<unsigned char const *>(signing_input.data()),
                                      signing_input.size());
        signature = getBackEnd().sign(alg, key, signing_span);
    }
    // else: none algorithm → empty signature

    return SignAttorney::construct(vector<unsigned char>(payload.begin(), payload.end()),
                                   alg,
                                   kid,
                                   type,
                                   header_params,
                                   header_b64,
                                   payload_b64,
                                   signature);
}

JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::vector<unsigned char> const &payload)
{
    return sign(key, alg, "", {}, std::span<unsigned char const>(payload.data(), payload.size()));
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::vector<unsigned char> const &payload)
{
    return sign(key, alg, type, {}, std::span<unsigned char const>(payload.data(), payload.size()));
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::map<std::string, std::string> const &header_params,
         std::string const &payload)
{
    return sign(key, alg, type, header_params, span<char const>(payload.data(), payload.size()));
}

JWS sign(JWK const &key, JWA::SignatureAlgorithm alg, std::string const &payload)
{
    return sign(key, alg, "", {}, std::span<char const>(payload.data(), payload.size()));
}

JWS sign(JWK const &key,
         JWA::SignatureAlgorithm alg,
         std::string const &type,
         std::string const &payload)
{
    return sign(key, alg, type, {}, std::span<char const>(payload.data(), payload.size()));
}

ostream &operator<<(ostream &os, JWS const &jws)
{
    os << jws.toCompact();
    return os;
}
bool operator==(JWS const &lhs, JWS const &rhs)
{
    string const lhs_compact = lhs.toCompact();
    string const rhs_compact = rhs.toCompact();
    return lhs_compact == rhs_compact;
}

bool operator!=(JWS const &lhs, JWS const &rhs)
{
    return !(lhs == rhs);
}

bool operator<(JWS const &lhs, JWS const &rhs)
{
    return lhs.toCompact() < rhs.toCompact();
}

bool operator<=(JWS const &lhs, JWS const &rhs)
{
    return lhs.toCompact() <= rhs.toCompact();
}

bool operator>(JWS const &lhs, JWS const &rhs)
{
    return lhs.toCompact() > rhs.toCompact();
}

bool operator>=(JWS const &lhs, JWS const &rhs)
{
    return lhs.toCompact() >= rhs.toCompact();
}

}  // namespace JOSE
}  // namespace Vlinder
