#include "jwk_set.hpp"

#include <variant>

#include "jwe.hpp"
#include "private/json_utils.hpp"
#include "private/result.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;
using Vlinder::JOSE::Private::makeError;
using Vlinder::JOSE::Private::makeOk;

namespace Vlinder {
namespace JOSE {

namespace {
pair<optional<JWKSet>, string> fromJSON_(string const &json_string, bool ignore_private_if_present)
{
    json jwk_set_json = json::parse(json_string, nullptr, false);
    if (jwk_set_json.is_discarded())
        return makeError<JWKSet>("JWKSet fromJSON: invalid JSON");

    if (!jwk_set_json.is_object())
        return makeError<JWKSet>("JWKSet fromJSON: expected a JSON object");

    if (!jwk_set_json.contains("keys"))
        return makeError<JWKSet>("JWKSet fromJSON: missing 'keys' array");

    if (!jwk_set_json["keys"].is_array())
        return makeError<JWKSet>("JWKSet fromJSON: 'keys' field must be an array");

    JWKSet set;
    for (auto const &key_json : jwk_set_json["keys"])
    {
        string key_json_string = key_json.dump();
        auto jwk = JWK::fromJSON(key_json_string, ignore_private_if_present, nothrow);
        if (jwk.has_value())
        {
            set.addKey(*jwk);
        }
        else
        {
            auto jwe = JWE::fromJSON(key_json_string, nothrow);
            if (!jwe.has_value())
                return makeError<JWKSet>("JWKSet fromJSON: failed to parse key as JWK or JWE: " +
                                         key_json_string);
            set.addKey(*jwe);
        }
    }
    return makeOk<JWKSet>(std::move(set));
}
}  // namespace

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
    auto [set_opt, set_err] = fromJSON_(json_string, ignore_private_if_present);
    if (!set_opt)
        throw runtime_error(set_err);  // throwing wrapper
    return std::move(*set_opt);
}

optional<JWKSet>
JWKSet::fromJSON(string const &json, bool ignore_private_if_present, nothrow_t const &) noexcept
{
    return fromJSON_(json, ignore_private_if_present).first;
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
