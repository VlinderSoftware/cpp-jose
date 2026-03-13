#include "jwt.hpp"

#include <algorithm>
#include <map>
#include <stdexcept>

#include "base64url.hpp"
#include "private/json_utils.hpp"
#include "jwa.hpp"
#include "jwk.hpp"
#include "jws.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;
namespace Vlinder {
namespace JOSE {

namespace {

int64_t timePointToTimestamp(chrono::system_clock::time_point tp)
{
    auto duration = tp.time_since_epoch();
    return chrono::duration_cast<chrono::seconds>(duration).count();
}

chrono::system_clock::time_point timestampToTimePoint(int64_t timestamp)
{
    return chrono::system_clock::time_point(chrono::seconds(timestamp));
}

}  // anonymous namespace

struct JWT::Impl
{
    map<string, json> claims_;

    void setClaim(string const &name, json const &value)
    {
        claims_[name] = value;
    }

    json getClaim(string const &name) const
    {
        auto it = claims_.find(name);
        if (it != claims_.end())
        {
            return it->second;
        }
        return json();
    }

    bool hasClaim(string const &name) const
    {
        return claims_.find(name) != claims_.end();
    }
};

JWT::JWT() : impl_(make_unique<Impl>())
{
}

JWT::~JWT() = default;

JWT::JWT(const JWT &other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWT &JWT::operator=(const JWT &other)
{
    if (this != &other)
    {
        impl_ = make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWT::JWT(JWT &&other) noexcept = default;
JWT &JWT::operator=(JWT &&other) noexcept = default;

void JWT::setIssuer(string const &iss)
{
    impl_->setClaim("iss", iss);
}

void JWT::setSubject(string const &sub)
{
    impl_->setClaim("sub", sub);
}

void JWT::setAudience(string const &aud)
{
    impl_->setClaim("aud", aud);
}

void JWT::setAudience(vector<string> const &aud)
{
    if (aud.empty())
    {
        return;
    }

    if (aud.size() == 1)
    {
        impl_->setClaim("aud", aud[0]);
    }
    else
    {
        json aud_array = json::array();
        for (auto const &a : aud)
        {
            aud_array.push_back(a);
        }
        impl_->setClaim("aud", aud_array);
    }
}

void JWT::setExpiration(chrono::system_clock::time_point exp)
{
    impl_->setClaim("exp", static_cast<int>(timePointToTimestamp(exp)));
}

void JWT::setNotBefore(chrono::system_clock::time_point nbf)
{
    impl_->setClaim("nbf", static_cast<int>(timePointToTimestamp(nbf)));
}

void JWT::setIssuedAt(chrono::system_clock::time_point iat)
{
    impl_->setClaim("iat", static_cast<int>(timePointToTimestamp(iat)));
}

void JWT::setJWTID(string const &jti)
{
    impl_->setClaim("jti", jti);
}

void JWT::setClaim(string const &name, string const &value)
{
    impl_->setClaim(name, value);
}

string JWT::getIssuer() const
{
    json claim = impl_->getClaim("iss");
    if (claim.is_string())
    {
        return claim.get<string>();
    }
    return "";
}

string JWT::getSubject() const
{
    json claim = impl_->getClaim("sub");
    if (claim.is_string())
    {
        return claim.get<string>();
    }
    return "";
}

vector<string> JWT::getAudience() const
{
    json claim = impl_->getClaim("aud");
    vector<string> result;

    if (claim.is_string())
    {
        result.push_back(claim.get<string>());
    }
    else if (claim.is_array())
    {
        // Proper array iteration with nlohmann::json
        for (auto const &elem : claim)
        {
            if (elem.is_string())
            {
                result.push_back(elem.get<string>());
            }
        }
    }

    return result;
}

chrono::system_clock::time_point JWT::getExpiration() const
{
    json claim = impl_->getClaim("exp");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return chrono::system_clock::time_point();
}

chrono::system_clock::time_point JWT::getNotBefore() const
{
    json claim = impl_->getClaim("nbf");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return chrono::system_clock::time_point();
}

chrono::system_clock::time_point JWT::getIssuedAt() const
{
    json claim = impl_->getClaim("iat");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return chrono::system_clock::time_point();
}

string JWT::getJWTID() const
{
    json claim = impl_->getClaim("jti");
    if (claim.is_string())
    {
        return claim.get<string>();
    }
    return "";
}

string JWT::getClaim(string const &name) const
{
    json claim = impl_->getClaim(name);
    if (claim.is_string())
    {
        return claim.get<string>();
    }
    return "";
}

bool JWT::hasClaim(string const &name) const
{
    return impl_->hasClaim(name);
}

string JWT::sign(const JWK &key, string const &algorithm) const
{
    // Build claims JSON
    json claims_json = json::object();

    for (auto const &claim : impl_->claims_)
    {
        claims_json[claim.first] = claim.second;
    }

    string payload = claims_json.dump();

    // Create JWS
    JWS jws;
    jws.setPayload(payload);
    jws.setType("JWT");

    // Determine algorithm: if "RS256" default is used but key is not RSA, pick appropriate
    // algorithm
    string actual_algorithm = algorithm;
    if (algorithm == "RS256")  // This is the default
    {
        JWK::KeyType key_type = key.getKeyType();
        if (key_type == JWK::KeyType::oct)
        {
            actual_algorithm = "HS256";
        }
        else if (key_type == JWK::KeyType::ec)
        {
            actual_algorithm = "ES256";
        }
        // Otherwise keep RS256 for RSA keys
    }

    jws.setAlgorithm(JWA::signatureAlgorithmFromString(actual_algorithm));

    // Copy key ID if present
    string kid = key.getKeyID();
    if (!kid.empty())
    {
        jws.setKeyID(kid);
    }

    return jws.sign(key);
}

JWT JWT::verify(string const &jwt, const JWK &key)
{
    // Verify using JWS
    if (!JWS::verify(jwt, key))
    {
        throw runtime_error("JWT signature verification failed");
    }

    // Parse if verification succeeded
    return parse(jwt);
}

JWT JWT::parse(string const &jwt)
{
    // Parse as JWS
    JWS jws = JWS::parse(jwt);

    // Parse payload as JSON
    string payload = jws.getPayload();
    json claims_json = json::parse(payload);

    if (!claims_json.is_object())
    {
        throw runtime_error("JWT payload is not a JSON object");
    }

    JWT result;

    // Extract claims using nlohmann::json iteration
    // Standard claims
    if (claims_json.contains("iss") && claims_json["iss"].is_string())
    {
        result.setIssuer(claims_json["iss"].get<string>());
    }
    if (claims_json.contains("sub") && claims_json["sub"].is_string())
    {
        result.setSubject(claims_json["sub"].get<string>());
    }
    if (claims_json.contains("aud"))
    {
        if (claims_json["aud"].is_string())
        {
            result.setAudience(claims_json["aud"].get<string>());
        }
        else if (claims_json["aud"].is_array())
        {
            vector<string> audiences;
            for (auto const &elem : claims_json["aud"])
            {
                if (elem.is_string())
                {
                    audiences.push_back(elem.get<string>());
                }
            }
            result.setAudience(audiences);
        }
    }
    if (claims_json.contains("exp") && claims_json["exp"].is_number())
    {
        result.setExpiration(
            timestampToTimePoint(static_cast<int64_t>(claims_json["exp"].get<int>())));
    }
    if (claims_json.contains("nbf") && claims_json["nbf"].is_number())
    {
        result.setNotBefore(
            timestampToTimePoint(static_cast<int64_t>(claims_json["nbf"].get<int>())));
    }
    if (claims_json.contains("iat") && claims_json["iat"].is_number())
    {
        result.setIssuedAt(
            timestampToTimePoint(static_cast<int64_t>(claims_json["iat"].get<int>())));
    }
    if (claims_json.contains("jti") && claims_json["jti"].is_string())
    {
        result.setJWTID(claims_json["jti"].get<string>());
    }

    // Store all claims directly
    for (auto it = claims_json.begin(); it != claims_json.end(); ++it)
    {
        result.impl_->claims_[it.key()] = it.value();
    }

    return result;
}

bool JWT::validate(string const &issuer, string const &audience, int leeway) const
{
    auto now = chrono::system_clock::now();

    // Check issuer if provided
    if (!issuer.empty())
    {
        if (getIssuer() != issuer)
        {
            return false;
        }
    }

    // Check audience if provided
    if (!audience.empty())
    {
        vector<string> audiences = getAudience();
        if (audiences.empty())
        {
            return false;
        }

        bool found = false;
        for (auto const &aud : audiences)
        {
            if (aud == audience)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            return false;
        }
    }

    // Check expiration time
    auto exp = getExpiration();
    if (exp != chrono::system_clock::time_point())
    {
        auto exp_with_leeway = exp + chrono::seconds(leeway);
        if (now > exp_with_leeway)
        {
            return false;
        }
    }

    // Check not before time
    auto nbf = getNotBefore();
    if (nbf != chrono::system_clock::time_point())
    {
        auto nbf_with_leeway = nbf - chrono::seconds(leeway);
        if (now < nbf_with_leeway)
        {
            return false;
        }
    }

    return true;
}

}  // namespace JOSE
}  // namespace Vlinder
