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
    Impl() = default;
    Impl(vector<unsigned char> const &payload,
         JWA::SignatureAlgorithm algorithm,
         string const &kid,
         string const &typ,
         map<string, string> const &header_params,
         string const &header_b64,
         string const &payload_b64,
         vector<unsigned char> const &signature)
        : payload_(payload), algorithm_(algorithm), kid_(kid), typ_(typ),
          header_params_(header_params), header_b64_(header_b64), payload_b64_(payload_b64),
          signature_(signature)
    {
    }

    vector<unsigned char> payload_;
    JWA::SignatureAlgorithm algorithm_ = JWA::SignatureAlgorithm::rs256;
    string kid_;
    string typ_;
    map<string, string> header_params_;
    string header_b64_;
    string payload_b64_;
    vector<unsigned char> signature_;
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
    auto impl = make_unique<JWS::Impl>(move(payload),
                                       alg,
                                       move(kid),
                                       move(typ),
                                       move(header_params),
                                       move(header_b64),
                                       move(payload_b64),
                                       move(signature));
    return JWS(move(impl));
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
    return impl_->header_b64_ + "." + impl_->payload_b64_ + "." +
           Base64URL::encode(impl_->signature_);
}

string JWS::toJSON(bool flattened) const
{
    string const sig_b64 = Base64URL::encode(impl_->signature_);
    if (flattened)
    {
        json j = json::object();
        j["payload"] = impl_->payload_b64_;
        j["protected"] = impl_->header_b64_;
        j["signature"] = sig_b64;
        return j.dump();
    }
    json sig_obj = json::object();
    sig_obj["protected"] = impl_->header_b64_;
    sig_obj["signature"] = sig_b64;
    json j = json::object();
    j["payload"] = impl_->payload_b64_;
    j["signatures"] = json::array({sig_obj});
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
    return JWS(make_unique<Impl>(move(impl)));
}

pair<optional<JWS>, bool> JWS::fromCompact(string const &compact, nothrow_t const &) noexcept
{
    try
    {
        return {fromCompact(compact), true};
    }
    catch (...)
    {
        return {nullopt, false};
    }
}

JWS JWS::fromJSON(string const &json_str)
{
    json j = json::parse(json_str);

    string payload_b64;
    string header_b64;
    string sig_b64;

    if (j.contains("signatures"))
    {
        // General JWS JSON serialization
        payload_b64 = j["payload"].get<string>();
        auto const &sigs = j["signatures"];
        if (sigs.empty())
        {
            throw runtime_error("JWS JSON has no signatures");
        }
        auto const &first = sigs[0];
        header_b64 = first["protected"].get<string>();
        sig_b64 = first["signature"].get<string>();
    }
    else
    {
        // Flattened JWS JSON serialization
        payload_b64 = j["payload"].get<string>();
        header_b64 = j["protected"].get<string>();
        sig_b64 = j["signature"].get<string>();
    }

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

pair<optional<JWS>, bool> JWS::fromJSON(string const &json_str, nothrow_t const &) noexcept
{
    try
    {
        return {fromJSON(json_str), true};
    }
    catch (...)
    {
        return {nullopt, false};
    }
}

pair<optional<JWS>, bool> JWS::tryLoad(string const &input) noexcept
{
    auto [jws, ok] = fromCompact(input, nothrow);
    if (ok)
    {
        return {std::move(jws), true};
    }
    return fromJSON(input, nothrow);
}

JWS::JWS(unique_ptr<Impl> impl) : impl_(std::move(impl))
{
}

bool verify(JWS const &jws, JWK const &key)
{
    auto const &impl = *jws.impl_;
    // Reject none-algorithm to prevent algorithm-confusion attacks (RFC 7515 §8.4)
    if (impl.algorithm_ == JWA::SignatureAlgorithm::none)
    {
        return false;
    }
    string const signing_input = impl.header_b64_ + "." + impl.payload_b64_;
    vector<unsigned char> const signing_input_bytes(signing_input.begin(), signing_input.end());
    return getBackEnd().verify(impl.algorithm_, key, signing_input_bytes, impl.signature_);
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

}  // namespace JOSE
}  // namespace Vlinder
