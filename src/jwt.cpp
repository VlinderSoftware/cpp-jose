#include "jose/jwt.hpp"
#include "jose/jwk.hpp"
#include "jose/jws.hpp"
#include "jose/jwa.hpp"
#include "jose/json_utils.hpp"
#include "jose/base64url.hpp"
#include <stdexcept>
#include <map>
#include <algorithm>

namespace Vlinder
{
namespace jose
{

namespace
{

// Maximum audience entries when parsing JWT audience arrays
// This is a workaround for the limited JsonValue API which doesn't provide iteration
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

} // anonymous namespace

struct JWT::Impl
{
    std::map<std::string, JsonValue> claims;
    
    void setClaim(const std::string& name, const JsonValue& value)
    {
        claims[name] = value;
    }
    
    JsonValue getClaim(const std::string& name) const
    {
        auto it = claims.find(name);
        if (it != claims.end())
        {
            return it->second;
        }
        return JsonValue();
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
    impl_->setClaim("iss", JsonValue(iss));
}

void JWT::setSubject(const std::string& sub)
{
    impl_->setClaim("sub", JsonValue(sub));
}

void JWT::setAudience(const std::string& aud)
{
    impl_->setClaim("aud", JsonValue(aud));
}

void JWT::setAudience(const std::vector<std::string>& aud)
{
    if (aud.empty())
    {
        return;
    }
    
    if (aud.size() == 1)
    {
        impl_->setClaim("aud", JsonValue(aud[0]));
    }
    else
    {
        JsonValue audArray;
        audArray.setArray();
        for (const auto& a : aud)
        {
            audArray.append(JsonValue(a));
        }
        impl_->setClaim("aud", audArray);
    }
}

void JWT::setExpiration(std::chrono::system_clock::time_point exp)
{
    impl_->setClaim("exp", JsonValue(static_cast<int>(timePointToTimestamp(exp))));
}

void JWT::setNotBefore(std::chrono::system_clock::time_point nbf)
{
    impl_->setClaim("nbf", JsonValue(static_cast<int>(timePointToTimestamp(nbf))));
}

void JWT::setIssuedAt(std::chrono::system_clock::time_point iat)
{
    impl_->setClaim("iat", JsonValue(static_cast<int>(timePointToTimestamp(iat))));
}

void JWT::setJwtId(const std::string& jti)
{
    impl_->setClaim("jti", JsonValue(jti));
}

void JWT::setClaim(const std::string& name, const std::string& value)
{
    impl_->setClaim(name, JsonValue(value));
}

std::string JWT::getIssuer() const
{
    JsonValue claim = impl_->getClaim("iss");
    if (claim.isString())
    {
        return claim.asString();
    }
    return "";
}

std::string JWT::getSubject() const
{
    JsonValue claim = impl_->getClaim("sub");
    if (claim.isString())
    {
        return claim.asString();
    }
    return "";
}

std::vector<std::string> JWT::getAudience() const
{
    JsonValue claim = impl_->getClaim("aud");
    std::vector<std::string> result;
    
    if (claim.isString())
    {
        result.push_back(claim.asString());
    }
    else if (claim.isArray())
    {
        // Manual array iteration through JSON structure
        std::string serialized = claim.serialize();
        JsonValue reparsed = JsonValue::parse(serialized);
        
        // Note: Limited by JsonValue API which doesn't provide proper iteration
        for (size_t i = 0; i < MAX_AUDIENCE_ENTRIES; ++i)
        {
            try
            {
                JsonValue elem = reparsed[i];
                if (elem.isNull())
                {
                    break;
                }
                if (elem.isString())
                {
                    result.push_back(elem.asString());
                }
            }
            catch (...)
            {
                break;
            }
        }
    }
    
    return result;
}

std::chrono::system_clock::time_point JWT::getExpiration() const
{
    JsonValue claim = impl_->getClaim("exp");
    if (claim.isNumber())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.asNumber()));
    }
    return std::chrono::system_clock::time_point();
}

std::chrono::system_clock::time_point JWT::getNotBefore() const
{
    JsonValue claim = impl_->getClaim("nbf");
    if (claim.isNumber())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.asNumber()));
    }
    return std::chrono::system_clock::time_point();
}

std::chrono::system_clock::time_point JWT::getIssuedAt() const
{
    JsonValue claim = impl_->getClaim("iat");
    if (claim.isNumber())
    {
        return timestampToTimePoint(static_cast<int64_t>(claim.asNumber()));
    }
    return std::chrono::system_clock::time_point();
}

std::string JWT::getJwtId() const
{
    JsonValue claim = impl_->getClaim("jti");
    if (claim.isString())
    {
        return claim.asString();
    }
    return "";
}

std::string JWT::getClaim(const std::string& name) const
{
    JsonValue claim = impl_->getClaim(name);
    if (claim.isString())
    {
        return claim.asString();
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
    JsonValue claimsJson;
    claimsJson.setObject();
    
    for (const auto& claim : impl_->claims)
    {
        claimsJson.set(claim.first, claim.second);
    }
    
    std::string payload = claimsJson.serialize();
    
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
    JsonValue claimsJson = JsonValue::parse(payload);
    
    if (!claimsJson.isObject())
    {
        throw std::runtime_error("JWT payload is not a JSON object");
    }
    
    JWT result;
    
    // We need to manually extract all claims from the JSON object
    // Since JsonValue doesn't provide iteration, we'll parse the serialized form
    std::string serialized = claimsJson.serialize();
    JsonValue reparsed = JsonValue::parse(serialized);
    
    // Standard claims
    if (reparsed.has("iss") && reparsed["iss"].isString())
    {
        result.setIssuer(reparsed["iss"].asString());
    }
    if (reparsed.has("sub") && reparsed["sub"].isString())
    {
        result.setSubject(reparsed["sub"].asString());
    }
    if (reparsed.has("aud"))
    {
        if (reparsed["aud"].isString())
        {
            result.setAudience(reparsed["aud"].asString());
        }
        else if (reparsed["aud"].isArray())
        {
            std::vector<std::string> audiences;
            for (size_t i = 0; i < MAX_AUDIENCE_ENTRIES; ++i)
            {
                try
                {
                    JsonValue elem = reparsed["aud"][i];
                    if (elem.isNull()) break;
                    if (elem.isString())
                    {
                        audiences.push_back(elem.asString());
                    }
                }
                catch (...) { break; }
            }
            result.setAudience(audiences);
        }
    }
    if (reparsed.has("exp") && reparsed["exp"].isNumber())
    {
        result.setExpiration(timestampToTimePoint(static_cast<int64_t>(reparsed["exp"].asNumber())));
    }
    if (reparsed.has("nbf") && reparsed["nbf"].isNumber())
    {
        result.setNotBefore(timestampToTimePoint(static_cast<int64_t>(reparsed["nbf"].asNumber())));
    }
    if (reparsed.has("iat") && reparsed["iat"].isNumber())
    {
        result.setIssuedAt(timestampToTimePoint(static_cast<int64_t>(reparsed["iat"].asNumber())));
    }
    if (reparsed.has("jti") && reparsed["jti"].isString())
    {
        result.setJwtId(reparsed["jti"].asString());
    }
    
    // Store claims we extracted
    // Note: Full custom claim extraction would require a better JSON iteration API
    if (reparsed.has("iss")) result.impl_->claims["iss"] = reparsed["iss"];
    if (reparsed.has("sub")) result.impl_->claims["sub"] = reparsed["sub"];
    if (reparsed.has("aud")) result.impl_->claims["aud"] = reparsed["aud"];
    if (reparsed.has("exp")) result.impl_->claims["exp"] = reparsed["exp"];
    if (reparsed.has("nbf")) result.impl_->claims["nbf"] = reparsed["nbf"];
    if (reparsed.has("iat")) result.impl_->claims["iat"] = reparsed["iat"];
    if (reparsed.has("jti")) result.impl_->claims["jti"] = reparsed["jti"];
    
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

} // namespace jose
} // namespace Vlinder
