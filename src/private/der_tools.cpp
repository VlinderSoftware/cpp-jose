#include "der_tools.hpp"

#include "base64url.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

void appendDERLength(std::vector<unsigned char> &out, size_t length)
{
    if (length < 0x80)
    {
        out.push_back(static_cast<unsigned char>(length));
        return;
    }

    unsigned char encoded[sizeof(size_t)] = {};
    size_t count = 0;
    size_t value = length;
    while (value != 0)
    {
        encoded[count++] = static_cast<unsigned char>(value & 0xFF);
        value >>= 8;
    }

    out.push_back(static_cast<unsigned char>(0x80 | count));
    for (size_t i = 0; i < count; ++i)
    {
        out.push_back(encoded[count - 1 - i]);
    }
}

void appendDERInteger(std::vector<unsigned char> &out, std::vector<unsigned char> const &value)
{
    std::vector<unsigned char> normalized = value;
    while (normalized.size() > 1 && normalized[0] == 0)
    {
        normalized.erase(normalized.begin());
    }

    if (normalized.empty())
    {
        normalized.push_back(0);
    }

    if ((normalized[0] & 0x80) != 0)
    {
        normalized.insert(normalized.begin(), 0);
    }

    out.push_back(0x02);
    appendDERLength(out, normalized.size());
    out.insert(out.end(), normalized.begin(), normalized.end());
}

std::vector<unsigned char> buildRSAPrivateKeyPKCS1DERFromJSON(json const &json)
{
    using Base64Url = Vlinder::JOSE::Base64Url;

    auto n = Base64Url::decode(json.at("n").get<std::string>());
    auto e = Base64Url::decode(json.at("e").get<std::string>());
    auto d = Base64Url::decode(json.at("d").get<std::string>());
    auto p = Base64Url::decode(json.at("p").get<std::string>());
    auto q = Base64Url::decode(json.at("q").get<std::string>());
    auto dp = Base64Url::decode(json.at("dp").get<std::string>());
    auto dq = Base64Url::decode(json.at("dq").get<std::string>());
    auto qi = Base64Url::decode(json.at("qi").get<std::string>());

    std::vector<unsigned char> body;
    appendDERInteger(body, std::vector<unsigned char>{0});
    appendDERInteger(body, n);
    appendDERInteger(body, e);
    appendDERInteger(body, d);
    appendDERInteger(body, p);
    appendDERInteger(body, q);
    appendDERInteger(body, dp);
    appendDERInteger(body, dq);
    appendDERInteger(body, qi);

    std::vector<unsigned char> der;
    der.push_back(0x30);
    appendDERLength(der, body.size());
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

}
}
}