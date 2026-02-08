#include "jose/jws.hpp"

#include <map>
#include <sstream>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwa.hpp"
#include "jose/jwk.hpp"

namespace Vlinder {
namespace jose {

struct JWS::Impl
{
    std::string payload;
    JWA::SignatureAlgorithm algorithm = JWA::SignatureAlgorithm::RS256;
    std::string kid;
    std::string typ;
    std::map<std::string, std::string> headerParams;
    std::string headerJson;
};

JWS::JWS() : impl_(std::make_unique<Impl>())
{
}

JWS::~JWS() = default;

JWS::JWS(const JWS& other) : impl_(std::make_unique<Impl>(*other.impl_))
{
}

JWS& JWS::operator=(const JWS& other)
{
    if (this != &other)
    {
        impl_ = std::make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWS::JWS(JWS&& other) noexcept = default;
JWS& JWS::operator=(JWS&& other) noexcept = default;

void JWS::setPayload(const std::string& payload)
{
    impl_->payload = payload;
}

void JWS::setAlgorithm(JWA::SignatureAlgorithm algorithm)
{
    impl_->algorithm = algorithm;
}

void JWS::setKeyId(const std::string& kid)
{
    impl_->kid = kid;
}

void JWS::setType(const std::string& typ)
{
    impl_->typ = typ;
}

void JWS::setHeaderParam(const std::string& name, const std::string& value)
{
    impl_->headerParams[name] = value;
}

std::string JWS::sign(const JWK& key) const
{
    // Build JOSE header
    JsonValue header;
    header.setObject();
    header.set("alg", JsonValue(JWA::toString(impl_->algorithm)));

    if (!impl_->typ.empty())
    {
        header.set("typ", JsonValue(impl_->typ));
    }

    if (!impl_->kid.empty())
    {
        header.set("kid", JsonValue(impl_->kid));
    }

    // Add custom header parameters
    for (const auto& param : impl_->headerParams)
    {
        header.set(param.first, JsonValue(param.second));
    }

    std::string headerJson = header.serialize();
    std::string encodedHeader = Base64Url::encode(headerJson);
    std::string encodedPayload = Base64Url::encode(impl_->payload);

    // Create signing input
    std::string signingInput = encodedHeader + "." + encodedPayload;
    std::vector<unsigned char> signingInputBytes(signingInput.begin(), signingInput.end());

    // Sign
    std::vector<unsigned char> signature;
    if (impl_->algorithm == JWA::SignatureAlgorithm::None)
    {
        signature.clear();
    }
    else
    {
        signature = JWA::sign(impl_->algorithm, key, signingInputBytes);
    }

    std::string encodedSignature = Base64Url::encode(signature);

    // Return compact serialization
    return signingInput + "." + encodedSignature;
}

bool JWS::verify(const std::string& jws, const JWK& key)
{
    try
    {
        // Split into three parts
        size_t firstDot = jws.find('.');
        size_t secondDot = jws.find('.', firstDot + 1);

        if (firstDot == std::string::npos || secondDot == std::string::npos)
        {
            return false;
        }

        std::string encodedHeader = jws.substr(0, firstDot);
        std::string encodedPayload = jws.substr(firstDot + 1, secondDot - firstDot - 1);
        std::string encodedSignature = jws.substr(secondDot + 1);

        // Decode header to get algorithm
        std::string headerJson = Base64Url::decodeToString(encodedHeader);
        JsonValue header = JsonValue::parse(headerJson);

        if (!header.has("alg"))
        {
            return false;
        }

        std::string algStr = header["alg"].asString();
        JWA::SignatureAlgorithm algorithm = JWA::signatureAlgorithmFromString(algStr);

        // Handle "none" algorithm
        if (algorithm == JWA::SignatureAlgorithm::None)
        {
            return encodedSignature.empty();
        }

        // Decode signature
        std::vector<unsigned char> signature = Base64Url::decode(encodedSignature);

        // Verify
        std::string signingInput = encodedHeader + "." + encodedPayload;
        std::vector<unsigned char> signingInputBytes(signingInput.begin(), signingInput.end());

        return JWA::verify(algorithm, key, signingInputBytes, signature);
    }
    catch (...)
    {
        return false;
    }
}

JWS JWS::parse(const std::string& jws)
{
    // Split into three parts
    size_t firstDot = jws.find('.');
    size_t secondDot = jws.find('.', firstDot + 1);

    if (firstDot == std::string::npos || secondDot == std::string::npos)
    {
        throw std::runtime_error("Invalid JWS format");
    }

    std::string encodedHeader = jws.substr(0, firstDot);
    std::string encodedPayload = jws.substr(firstDot + 1, secondDot - firstDot - 1);

    // Decode
    std::string headerJson = Base64Url::decodeToString(encodedHeader);
    std::string payload = Base64Url::decodeToString(encodedPayload);

    // Parse header
    JsonValue header = JsonValue::parse(headerJson);

    JWS result;
    result.impl_->payload = payload;
    result.impl_->headerJson = headerJson;

    if (header.has("alg"))
    {
        std::string algStr = header["alg"].asString();
        result.impl_->algorithm = JWA::signatureAlgorithmFromString(algStr);
    }

    if (header.has("kid"))
    {
        result.impl_->kid = header["kid"].asString();
    }

    if (header.has("typ"))
    {
        result.impl_->typ = header["typ"].asString();
    }

    return result;
}

std::string JWS::getPayload() const
{
    return impl_->payload;
}

std::string JWS::getHeader() const
{
    if (!impl_->headerJson.empty())
    {
        return impl_->headerJson;
    }

    JsonValue header;
    header.setObject();
    header.set("alg", JsonValue(JWA::toString(impl_->algorithm)));

    if (!impl_->typ.empty())
    {
        header.set("typ", JsonValue(impl_->typ));
    }

    if (!impl_->kid.empty())
    {
        header.set("kid", JsonValue(impl_->kid));
    }

    for (const auto& param : impl_->headerParams)
    {
        header.set(param.first, JsonValue(param.second));
    }

    return header.serialize();
}

JWA::SignatureAlgorithm JWS::getAlgorithm() const
{
    return impl_->algorithm;
}

}  // namespace jose
}  // namespace Vlinder
