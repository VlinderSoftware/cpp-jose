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

JWKSet::JWKSet(std::initializer_list<std::variant<JWK, JWE>> keys) : impl_(make_unique<Impl>())
{
    for (auto const &key : keys)
    {
        impl_->keys_.push_back(key);
    }
}

JWKSet::~JWKSet() = default;

JWKSet JWKSet::fromJSON(string const &json_string, bool ignore_private_if_present)
{
    JWKSet set;
    json jwk_set_json = json::parse(json_string);

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
        auto jwk = JWK::fromJSON(key_json_string, ignore_private_if_present, nothrow);
        if (!jwk.has_value())
        {
            auto jwe = JWE::fromJSON(key_json_string, nothrow);
            if (!jwe.has_value())
            {
                throw runtime_error("Failed to parse key as JWK or JWE");
            }
            else
            {
                set.addKey(*jwe);
            }
        }
        else
        {
            set.addKey(*jwk);
        }
    }

    return set;
}

optional<JWKSet> JWKSet::fromJSON(string const &json, bool ignore_private_if_present,
                                  nothrow_t const &) noexcept
{
    try
    {
        return optional<JWKSet>{JWKSet::fromJSON(json, ignore_private_if_present)};
    }
    catch (...)
    {
        return nullopt;
    }
}

void JWKSet::addKey(std::variant<JWK, JWE> const &key)
{
    impl_->keys_.push_back(key);
}

// does not.
variant<JWK, JWE> JWKSet::getKey(string const &kid, std::string const &alg) const
{
    auto predicate = [&kid, &alg](variant<JWK, JWE> const &key) -> bool
    {
        if (holds_alternative<JWK>(key))
        {
            const JWK &jwk = get<JWK>(key);
            return jwk.getKeyID() == kid && (alg.empty() || jwk.getAlgorithm() == alg);
        }
        // TODO if we want to support JWEs in the set, we would need to check if the JWE header
        // contains a kid and alg that match the parameters. else if (holds_alternative<JWE>(key))
        // {
        //     const JWE &jwe = get<JWE>(key);
        //     return jwe.getKeyID() == kid && (alg.empty() || jwe.getHeader().find("\"alg\":\"" +
        //     alg + "\"") != string::npos);
        // }
        return false;
    };
    auto where = find_if(impl_->keys_.begin(), impl_->keys_.end(), predicate);
    if (where == impl_->keys_.end())
    {
        throw runtime_error("Key not found");
    }
    return *where;
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
