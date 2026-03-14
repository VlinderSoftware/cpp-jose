#include "jws.hpp"

#include <map>
#include <sstream>
#include <stdexcept>

#include "base64url.hpp"
#include "jwa.hpp"
#include "jwk.hpp"
#include "private/json_utils.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

struct JWS::Impl
{
    string payload_;
    JWA::SignatureAlgorithm algorithm_ = JWA::SignatureAlgorithm::rs256;
    string kid_;
    string typ_;
    map<string, string> header_params_;
    string header_json_;
};

JWS::JWS() : impl_(make_unique<Impl>())
{
}

JWS::~JWS() = default;

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

JWS::JWS(JWS &&other) noexcept = default;
JWS &JWS::operator=(JWS &&other) noexcept = default;

void JWS::setPayload(string const &payload)
{
    impl_->payload_ = payload;
}

void JWS::setAlgorithm(JWA::SignatureAlgorithm algorithm)
{
    impl_->algorithm_ = algorithm;
}

void JWS::setKeyID(string const &kid)
{
    impl_->kid_ = kid;
}

void JWS::setType(string const &typ)
{
    impl_->typ_ = typ;
}

void JWS::setHeaderParam(string const &name, string const &value)
{
    impl_->header_params_[name] = value;
}

string JWS::sign(const JWK &key) const
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
    for (auto const &param : impl_->header_params_)
    {
        header[param.first] = param.second;
    }

    string header_json = header.dump();
    string encoded_header = Base64Url::encode(header_json);
    string encoded_payload = Base64Url::encode(impl_->payload_);

    // Create signing input
    string signing_input = encoded_header + "." + encoded_payload;
    vector<unsigned char> signing_input_bytes(signing_input.begin(), signing_input.end());

    // Sign
    vector<unsigned char> signature;
    if (impl_->algorithm_ == JWA::SignatureAlgorithm::none)
    {
        signature.clear();
    }
    else
    {
        signature = JWA::sign(impl_->algorithm_, key, signing_input_bytes);
    }

    string encoded_signature = Base64Url::encode(signature);

    // Return compact serialization
    return signing_input + "." + encoded_signature;
}

bool JWS::verify(string const &jws, const JWK &key)
{
    try
    {
        // Split into three parts
        size_t first_dot = jws.find('.');
        size_t second_dot = jws.find('.', first_dot + 1);

        if (first_dot == string::npos || second_dot == string::npos)
        {
            return false;
        }

        string encoded_header = jws.substr(0, first_dot);
        string encoded_payload = jws.substr(first_dot + 1, second_dot - first_dot - 1);
        string encoded_signature = jws.substr(second_dot + 1);

        // Decode header to get algorithm
        string header_json = Base64Url::decodeToString(encoded_header);
        json header = json::parse(header_json);

        if (!header.contains("alg"))
        {
            return false;
        }

        string alg_str = header["alg"].get<string>();
        JWA::SignatureAlgorithm algorithm = JWA::signatureAlgorithmFromString(alg_str);

        // Handle "none" algorithm — always reject when verify() is called
        // with a key: accepting an unsigned token when the caller supplies a
        // key is the classic algorithm-confusion / downgrade attack.
        if (algorithm == JWA::SignatureAlgorithm::none)
        {
            return false;
        }

        // Decode signature
        vector<unsigned char> signature = Base64Url::decode(encoded_signature);

        // Verify
        string signing_input = encoded_header + "." + encoded_payload;
        vector<unsigned char> signing_input_bytes(signing_input.begin(), signing_input.end());

        return JWA::verify(algorithm, key, signing_input_bytes, signature);
    }
    catch (...)
    {
        return false;
    }
}

JWS JWS::parse(string const &jws)
{
    // Split into three parts
    size_t first_dot = jws.find('.');
    size_t second_dot = jws.find('.', first_dot + 1);

    if (first_dot == string::npos || second_dot == string::npos)
    {
        throw runtime_error("Invalid JWS format");
    }

    string encoded_header = jws.substr(0, first_dot);
    string encoded_payload = jws.substr(first_dot + 1, second_dot - first_dot - 1);

    // Decode
    string header_json = Base64Url::decodeToString(encoded_header);
    string payload = Base64Url::decodeToString(encoded_payload);

    // Parse header
    json header = json::parse(header_json);

    JWS result;
    result.impl_->payload_ = payload;
    result.impl_->header_json_ = header_json;

    if (header.contains("alg"))
    {
        string alg_str = header["alg"].get<string>();
        result.impl_->algorithm_ = JWA::signatureAlgorithmFromString(alg_str);
    }

    if (header.contains("kid"))
    {
        result.impl_->kid_ = header["kid"].get<string>();
    }

    if (header.contains("typ"))
    {
        result.impl_->typ_ = header["typ"].get<string>();
    }

    return result;
}

string JWS::getPayload() const
{
    return impl_->payload_;
}

string JWS::getHeader() const
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

    for (auto const &param : impl_->header_params_)
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
