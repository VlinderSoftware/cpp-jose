#include "jose/jws.hpp"

#include <map>
#include <sstream>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwa.hpp"
#include "jose/jwk.hpp"

namespace Vlinder {
namespace JOSE {

struct JWS::Impl
{
    std::string payload_;
    JWA::SignatureAlgorithm algorithm_ = JWA::SignatureAlgorithm::rs256;
    std::string kid_;
    std::string typ_;
    std::map<std::string, std::string> header_params_;
    std::string header_json_;
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
    impl_->payload_ = payload;
}

void JWS::setAlgorithm(JWA::SignatureAlgorithm algorithm)
{
    impl_->algorithm_ = algorithm;
}

void JWS::setKeyID(const std::string& kid)
{
    impl_->kid_ = kid;
}

void JWS::setType(const std::string& typ)
{
    impl_->typ_ = typ;
}

void JWS::setHeaderParam(const std::string& name, const std::string& value)
{
    impl_->header_params_[name] = value;
}

std::string JWS::sign(const JWK& key) const
{
    // Build JOSE header
    json header = json::object();
    header["alg"] = JWA::toString(impl_->algorithm_);

    if (!impl_->typ_.empty())
    {
        header["typ"] = impl_->typ_;
    }

    if (!impl_->kid_.empty())
    {
        header["kid"] = impl_->kid_;
    }

    // Add custom header parameters
    for (const auto& param : impl_->header_params_)
    {
        header[param.first] = param.second;
    }

    std::string header_json = header.dump();
    std::string encoded_header = Base64Url::encode(header_json);
    std::string encoded_payload = Base64Url::encode(impl_->payload_);

    // Create signing input
    std::string signing_input = encoded_header + "." + encoded_payload;
    std::vector<unsigned char> signing_input_bytes(signing_input.begin(), signing_input.end());

    // Sign
    std::vector<unsigned char> signature;
    if (impl_->algorithm_ == JWA::SignatureAlgorithm::none)
    {
        signature.clear();
    }
    else
    {
        signature = JWA::sign(impl_->algorithm_, key, signing_input_bytes);
    }

    std::string encoded_signature = Base64Url::encode(signature);

    // Return compact serialization
    return signing_input + "." + encoded_signature;
}

bool JWS::verify(const std::string& jws, const JWK& key)
{
    try
    {
        // Split into three parts
        size_t first_dot = jws.find('.');
        size_t second_dot = jws.find('.', first_dot + 1);

        if (first_dot == std::string::npos || second_dot == std::string::npos)
        {
            return false;
        }

        std::string encoded_header = jws.substr(0, first_dot);
        std::string encoded_payload = jws.substr(first_dot + 1, second_dot - first_dot - 1);
        std::string encoded_signature = jws.substr(second_dot + 1);

        // Decode header to get algorithm
        std::string header_json = Base64Url::decodeToString(encoded_header);
        json header = json::parse(header_json);

        if (!header.contains("alg"))
        {
            return false;
        }

        std::string alg_str = header["alg"].get<std::string>();
        JWA::SignatureAlgorithm algorithm = JWA::signatureAlgorithmFromString(alg_str);

        // Handle "none" algorithm
        if (algorithm == JWA::SignatureAlgorithm::none)
        {
            return encoded_signature.empty();
        }

        // Decode signature
        std::vector<unsigned char> signature = Base64Url::decode(encoded_signature);

        // Verify
        std::string signing_input = encoded_header + "." + encoded_payload;
        std::vector<unsigned char> signing_input_bytes(signing_input.begin(), signing_input.end());

        return JWA::verify(algorithm, key, signing_input_bytes, signature);
    }
    catch (...)
    {
        return false;
    }
}

JWS JWS::parse(const std::string& jws)
{
    // Split into three parts
    size_t first_dot = jws.find('.');
    size_t second_dot = jws.find('.', first_dot + 1);

    if (first_dot == std::string::npos || second_dot == std::string::npos)
    {
        throw std::runtime_error("Invalid JWS format");
    }

    std::string encoded_header = jws.substr(0, first_dot);
    std::string encoded_payload = jws.substr(first_dot + 1, second_dot - first_dot - 1);

    // Decode
    std::string header_json = Base64Url::decodeToString(encoded_header);
    std::string payload = Base64Url::decodeToString(encoded_payload);

    // Parse header
    json header = json::parse(header_json);

    JWS result;
    result.impl_->payload_ = payload;
    result.impl_->header_json_ = header_json;

    if (header.contains("alg"))
    {
        std::string alg_str = header["alg"].get<std::string>();
        result.impl_->algorithm_ = JWA::signatureAlgorithmFromString(alg_str);
    }

    if (header.contains("kid"))
    {
        result.impl_->kid_ = header["kid"].get<std::string>();
    }

    if (header.contains("typ"))
    {
        result.impl_->typ_ = header["typ"].get<std::string>();
    }

    return result;
}

std::string JWS::getPayload() const
{
    return impl_->payload_;
}

std::string JWS::getHeader() const
{
    if (!impl_->header_json_.empty())
    {
        return impl_->header_json_;
    }

    json header = json::object();
    header["alg"] = JWA::toString(impl_->algorithm_);

    if (!impl_->typ_.empty())
    {
        header["typ"] = impl_->typ_;
    }

    if (!impl_->kid_.empty())
    {
        header["kid"] = impl_->kid_;
    }

    for (const auto& param : impl_->header_params_)
    {
        header[param.first] = param.second;
    }

    return header.dump();
}

JWA::SignatureAlgorithm JWS::getAlgorithm() const
{
    return impl_->algorithm_;
}

}  // namespace JOSE
}  // namespace Vlinder
