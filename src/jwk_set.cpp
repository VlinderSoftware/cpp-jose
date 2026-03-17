#include "jwk_set.hpp"
#include "jwk_thumbprint.hpp"

#include <cstring>
#include <set>
#include <stdexcept>

#include "base64url.hpp"
#include "private/back_end_factory.hpp"
#include "private/json_utils.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

// JWKSet implementation
struct JWKSet::Impl
{
    vector<JWK> keys_;
};

JWKSet::JWKSet() : impl_(make_unique<Impl>())
{
}

JWKSet::~JWKSet() = default;

JWKSet JWKSet::fromJSON(string const &json_str, bool ignore_private_if_present)
{
    JWKSet set;
    json jwk_set_json = json::parse(json_str);

    if (!jwk_set_json.contains("keys"))
    {
        throw runtime_error("Missing keys array");
    }

    if (!jwk_set_json["keys"].is_array())
    {
        throw runtime_error("keys field must be an array");
    }

    // Parse each key in the array
    for (auto const &keyJson : jwk_set_json["keys"])
    {
        string keyJsonStr = keyJson.dump();
        // TODO handle JWEs
        JWK key = JWK::fromJSON(keyJsonStr, ignore_private_if_present);
        set.addKey(key);
    }

    return set;
}

void JWKSet::addKey(const JWK &key)
{
    impl_->keys_.push_back(key);
}

// TODO add optional alg parameter: the combination of kid + alg has to be unique, kid by itself does not.
JWK JWKSet::getKey(string const &kid) const
{
    // TODO make this a find_if
    for (auto const &key : impl_->keys_)
    {
        if (key.getKeyID() == kid)
        {
            return key;
        }
    }
    throw runtime_error("Key not found");
}

vector<JWK> JWKSet::getKeys() const
{
    return impl_->keys_;
}

string JWKSet::toJSON() const
{
    json json_obj = json::object();

    json keys_array = json::array();

    for (auto const &key : impl_->keys_)
    {
        keys_array.push_back(json::parse(key.toJSON(false)));
    }

    json_obj["keys"] = keys_array;
    return json_obj.dump();
}

}  // namespace JOSE
}  // namespace Vlinder
