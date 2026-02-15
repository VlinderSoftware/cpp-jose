#include "jose/jwt.hpp"

#include <algorithm>
#include <map>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwa.hpp"
#include "jose/jwk.hpp"
#include "jose/jws.hpp"

namespace Vlinder {
namespace JOSE {

namespace {

int64_t timePointToTimestamp(std::chrono::system_clock::time_point tp)
{
    auto duration = tp.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

std::chrono::system_clock::time_point timestampToTimePoint(int64_t timestamp)
{
    return std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
}

}  // anonymous namespace

struct JWT::Impl
{
    std::map<std::string, json> claims_;

    void setClaim(const std::string& name, const json& value)
    {
        claims_[name] = value;
    }

    json getClaim(const std::string& name) const
    {
        auto it = claims_.find(name);
        if (it != claims_.end())
        {
            return it->second;
        }
        return json();
    }

    bool hasClaim(const std::string& name) const
    {
        return claims_.find(name) != claims_.end();
    }
};

JWT::JWT() : impl_(std::make_unique<Impl>())
{
}

JWT::~JWT() = default;

JWT::JWT(const JWT& other) : impl_(std::make_unique<Impl>(*other.impl_))
{
}

JWT& JWT::operator=(const JWT& other)
{
    if (this != &other)
    {
        impl_ = std::make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWT::JWT(JWT&& other) noexcept = default;
JWT& JWT::operator=(JWT&& other) noexcept = default;

void JWT::setIssuer(const std::string& iss)
{
    impl_->setClaim("iss", iss);
}

void JWT::setSubject(const std::string& sub)
{
    impl_->setClaim("sub", sub);
}

void JWT::setAudience(const std::string& aud)
{
    impl_->setClaim("aud", aud);
}

void JWT::setAudience(const std::vector<std::string>& aud)
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
        for (const auto& a : aud)
        {
            aud_array.push_back(a);
        }
        impl_->setClaim("aud", aud_array);
    }
}

void JWT::setExpiration(std::chrono::system_clock::time_point exp)
{
    impl_->setClaim("exp", static_cast<int>(timePointToTimestamp(exp)));
}

void JWT::setNotBefore(std::chrono::system_clock::time_point nbf)
{
    impl_->setClaim("nbf", static_cast<int>(timePointToTimestamp(nbf)));
}

void JWT::setIssuedAt(std::chrono::system_clock::time_point iat)
{
    impl_->setClaim("iat", static_cast<int>(timePointToTimestamp(iat)));
}

void JWT::setJWTID(const std::string& jti)
{
    impl_->setClaim("jti", jti);
}

void JWT::setClaim(const std::string& name, const std::string& value)
{
    impl_->setClaim(name, value);
}

std::string JWT::getIssuer() const
{
    json claim = impl_->getClaim("iss");
    if (claim.is_string())
    {
        return claim.get<std::string>();
    }
    return "";
}

std::string JWT::getSubject() const
{
    json claim = impl_->getClaim("sub");
    if (claim.is_string())
    {
        return claim.get<std::string>();
    }
    return "";
}

std::vector<std::string> JWT::getAudience() const
{
    json claim = impl_->getClaim("aud");
    std::vector<std::string> result;

    if (claim.is_string())
    {
        result.push_back(claim.get<std::string>());
    }
    else if (claim.is_array())
    {
        // Proper array iteration with nlohmann::json
        for (const auto& elem : claim)
        {
            if (elem.is_string())
            {
                result.push_back(elem.get<std::string>());
            }
        }
    }

    return result;
}

std::chrono::system_clock::time_point JWT::getExpiration() const
{
    json claim = impl_->getClaim("exp");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return std::chrono::system_clock::time_point();
}

std::chrono::system_clock::time_point JWT::getNotBefore() const
{
    json claim = impl_->getClaim("nbf");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return std::chrono::system_clock::time_point();
}

std::chrono::system_clock::time_point JWT::getIssuedAt() const
{
    json claim = impl_->getClaim("iat");
    if (claim.is_number())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.get<int>()));
    }
    return std::chrono::system_clock::time_point();
}

std::string JWT::getJWTID() const
{
    json claim = impl_->getClaim("jti");
    if (claim.is_string())
    {
        return claim.get<std::string>();
    }
    return "";
}

std::string JWT::getClaim(const std::string& name) const
{
    json claim = impl_->getClaim(name);
    if (claim.is_string())
    {
        return claim.get<std::string>();
    }
    return "";
}

bool JWT::hasClaim(const std::string& name) const
{
    return impl_->hasClaim(name);
}

std::string JWT::sign(const JWK& key, const std::string& algorithm) const
{
    // Build claims JSON
    json claims_json = json::object();

    for (const auto& claim : impl_->claims_)
    {
        claims_json[claim.first] = claim.second;
    }

    std::string payload = claims_json.dump();

    // Create JWS
    JWS jws;
    jws.setPayload(payload);
    jws.setType("JWT");
    
    // Determine algorithm: if "RS256" default is used but key is not RSA, pick appropriate algorithm
    std::string actual_algorithm = algorithm;
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
    std::string kid = key.getKeyID();
    if (!kid.empty())
    {
        jws.setKeyID(kid);
    }

    return jws.sign(key);
}

JWT JWT::verify(const std::string& jwt, const JWK& key)
{
    // Verify using JWS
    if (!JWS::verify(jwt, key))
    {
        throw std::runtime_error("JWT signature verification failed");
    }

    // Parse if verification succeeded
    return parse(jwt);
}

JWT JWT::parse(const std::string& jwt)
{
    // Parse as JWS
    JWS jws = JWS::parse(jwt);

    // Parse payload as JSON
    std::string payload = jws.getPayload();
    json claims_json = json::parse(payload);

    if (!claims_json.is_object())
    {
        throw std::runtime_error("JWT payload is not a JSON object");
    }

    JWT result;

    // Extract claims using nlohmann::json iteration
    // Standard claims
    if (claims_json.contains("iss") && claims_json["iss"].is_string())
    {
        result.setIssuer(claims_json["iss"].get<std::string>());
    }
    if (claims_json.contains("sub") && claims_json["sub"].is_string())
    {
        result.setSubject(claims_json["sub"].get<std::string>());
    }
    if (claims_json.contains("aud"))
    {
        if (claims_json["aud"].is_string())
        {
            result.setAudience(claims_json["aud"].get<std::string>());
        }
        else if (claims_json["aud"].is_array())
        {
            std::vector<std::string> audiences;
            for (const auto& elem : claims_json["aud"])
            {
                if (elem.is_string())
                {
                    audiences.push_back(elem.get<std::string>());
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
        result.setNotBefore(timestampToTimePoint(static_cast<int64_t>(claims_json["nbf"].get<int>())));
    }
    if (claims_json.contains("iat") && claims_json["iat"].is_number())
    {
        result.setIssuedAt(timestampToTimePoint(static_cast<int64_t>(claims_json["iat"].get<int>())));
    }
    if (claims_json.contains("jti") && claims_json["jti"].is_string())
    {
        result.setJWTID(claims_json["jti"].get<std::string>());
    }

    // Store all claims directly
    for (auto it = claims_json.begin(); it != claims_json.end(); ++it)
    {
        result.impl_->claims_[it.key()] = it.value();
    }

    return result;
}

bool JWT::validate(const std::string& issuer, const std::string& audience, int leeway) const
{
    auto now = std::chrono::system_clock::now();

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
        std::vector<std::string> audiences = getAudience();
        if (audiences.empty())
        {
            return false;
        }

        bool found = false;
        for (const auto& aud : audiences)
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
    if (exp != std::chrono::system_clock::time_point())
    {
        auto exp_with_leeway = exp + std::chrono::seconds(leeway);
        if (now > exp_with_leeway)
        {
            return false;
        }
    }

    // Check not before time
    auto nbf = getNotBefore();
    if (nbf != std::chrono::system_clock::time_point())
    {
        auto nbf_with_leeway = nbf - std::chrono::seconds(leeway);
        if (now < nbf_with_leeway)
        {
            return false;
        }
    }

    return true;
}

}  // namespace JOSE
}  // namespace Vlinder
