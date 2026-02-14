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

// Maximum audience entries when parsing JWT audience arrays
// No longer needed with nlohmann::json proper iteration
const size_t MAX_AUDIENCE_ENTRIES = 100;

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
    std::map<std::string, json> claims;

    void setClaim(const std::string& name, const json& value)
    {
        claims[name] = value;
    }

    json getClaim(const std::string& name) const
    {
        auto it = claims.find(name);
        if (it != claims.end())
        {
            return it->second;
        }
        return json();
    }

    bool hasClaim(const std::string& name) const
    {
        return claims.find(name) != claims.end();
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
        json audArray = json::array();
        for (const auto& a : aud)
        {
            audArray.push_back(a);
        }
        impl_->setClaim("aud", audArray);
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

void JWT::setJwtId(const std::string& jti)
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

std::string JWT::getJwtId() const
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
    json claimsJson = json::object();

    for (const auto& claim : impl_->claims)
    {
        claimsJson[claim.first] = claim.second;
    }

    std::string payload = claimsJson.dump();

    // Create JWS
    JWS jws;
    jws.setPayload(payload);
    jws.setType("JWT");
    jws.setAlgorithm(JWA::signatureAlgorithmFromString(algorithm));

    // Copy key ID if present
    std::string kid = key.getKeyId();
    if (!kid.empty())
    {
        jws.setKeyId(kid);
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
    json claimsJson = json::parse(payload);

    if (!claimsJson.is_object())
    {
        throw std::runtime_error("JWT payload is not a JSON object");
    }

    JWT result;

    // Extract claims using nlohmann::json iteration
    // Standard claims
    if (claimsJson.contains("iss") && claimsJson["iss"].is_string())
    {
        result.setIssuer(claimsJson["iss"].get<std::string>());
    }
    if (claimsJson.contains("sub") && claimsJson["sub"].is_string())
    {
        result.setSubject(claimsJson["sub"].get<std::string>());
    }
    if (claimsJson.contains("aud"))
    {
        if (claimsJson["aud"].is_string())
        {
            result.setAudience(claimsJson["aud"].get<std::string>());
        }
        else if (claimsJson["aud"].is_array())
        {
            std::vector<std::string> audiences;
            for (const auto& elem : claimsJson["aud"])
            {
                if (elem.is_string())
                {
                    audiences.push_back(elem.get<std::string>());
                }
            }
            result.setAudience(audiences);
        }
    }
    if (claimsJson.contains("exp") && claimsJson["exp"].is_number())
    {
        result.setExpiration(
            timestampToTimePoint(static_cast<int64_t>(claimsJson["exp"].get<int>())));
    }
    if (claimsJson.contains("nbf") && claimsJson["nbf"].is_number())
    {
        result.setNotBefore(timestampToTimePoint(static_cast<int64_t>(claimsJson["nbf"].get<int>())));
    }
    if (claimsJson.contains("iat") && claimsJson["iat"].is_number())
    {
        result.setIssuedAt(timestampToTimePoint(static_cast<int64_t>(claimsJson["iat"].get<int>())));
    }
    if (claimsJson.contains("jti") && claimsJson["jti"].is_string())
    {
        result.setJwtId(claimsJson["jti"].get<std::string>());
    }

    // Store all claims directly
    for (auto it = claimsJson.begin(); it != claimsJson.end(); ++it)
    {
        result.impl_->claims[it.key()] = it.value();
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
        auto expWithLeeway = exp + std::chrono::seconds(leeway);
        if (now > expWithLeeway)
        {
            return false;
        }
    }

    // Check not before time
    auto nbf = getNotBefore();
    if (nbf != std::chrono::system_clock::time_point())
    {
        auto nbfWithLeeway = nbf - std::chrono::seconds(leeway);
        if (now < nbfWithLeeway)
        {
            return false;
        }
    }

    return true;
}

}  // namespace JOSE
}  // namespace Vlinder
