#include "jwk_set.hpp"

#include <variant>

#include "jwe.hpp"
#include "private/json_utils.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;

namespace Vlinder {
namespace JOSE {

// JWKSet implementation
struct JWKSet::Impl
{
    vector<variant<JWK, JWE>> keys_;
};

JWKSet::JWKSet() : impl_(make_unique<Impl>())
{
}

JWKSet::JWKSet(std::initializer_list<JWK> keys) : impl_(make_unique<Impl>())
{
    for (auto const &key : keys)
    {
        impl_->keys_.push_back(key);
    }
}

JWKSet::JWKSet(std::initializer_list<JWE> keys) : impl_(make_unique<Impl>())
{
    for (auto const &key : keys)
    {
        impl_->keys_.push_back(key);
    }
}

JWKSet::JWKSet(std::initializer_list<std::variant<JWK, JWE>> keys) : impl_(make_unique<Impl>())
{
    for (auto const &key : keys)
    {
        impl_->keys_.push_back(key);
    }
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
    for (auto const &key_json : jwk_set_json["keys"])
    {
        string key_json_string = key_json.dump();
        // TODO handle JWEs
        auto jwk = JWK::fromJSON(key_json_string, ignore_private_if_present, nothrow);
        if (!jwk.second)
        {
            auto jwe = JWE::fromJSON(key_json_string, nothrow);
            if (!jwe.second)
            {
                throw runtime_error("Failed to parse key as JWK or JWE");
            }
            else
            {
                set.addKey(*jwe.first);
            }
        }
        else
        {
            set.addKey(*jwk.first);
        }
    }

    return set;
}

void JWKSet::addKey(std::variant<JWK, JWE> const &key)
{
    impl_->keys_.push_back(key);
}

// TODO add optional alg parameter: the combination of kid + alg has to be unique, kid by itself
// does not.
variant<JWK, JWE> JWKSet::getKey(string const &kid) const
{
    // TODO make this a find_if
    for (auto const &key : impl_->keys_)
    {
        if (holds_alternative<JWK>(key) && get<JWK>(key).getKeyID() == kid)
        {
            return get<JWK>(key);
        }
    }
    throw runtime_error("Key not found");
}

vector<std::variant<JWK, JWE>> JWKSet::getKeys() const
{
    return impl_->keys_;
}

string JWKSet::toJSON() const
{
    json json_obj = json::object();

    json keys_array = json::array();

    for (auto const &key : impl_->keys_)
    {
        if (holds_alternative<JWK>(key))
        {
            keys_array.push_back(json::parse(get<JWK>(key).toJSON(false)));
        }
        else if (holds_alternative<JWE>(key))
        {
            keys_array.push_back(json::parse(get<JWE>(key).toJSON()));
        }
    }

    json_obj["keys"] = keys_array;
    return json_obj.dump();
}

}  // namespace JOSE
}  // namespace Vlinder
