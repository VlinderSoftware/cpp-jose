#pragma once

#include <memory>
#include <string>

#include "jwk.hpp"
#include "private/back_end.hpp"

namespace Vlinder {
namespace JOSE {

struct JWK::Impl
{
    KeyType key_type_;
    std::unique_ptr<Private::Key> key_;
    std::string kid_;
    std::string alg_;
    Use use_;
    bool has_use_ = false;

    ~Impl() = default;

    Impl(KeyType key_type, Use use, std::string const &alg)
        : key_type_(key_type), use_(use), alg_(alg), has_use_(true)
    {
    }

    Impl(Impl const &other)
        : key_type_(other.key_type_), kid_(other.kid_), alg_(other.alg_), use_(other.use_),
          has_use_(other.has_use_)
    {
        if (other.key_)
        {
            key_ = other.key_->clone();
        }
    }
};

}  // namespace JOSE
}  // namespace Vlinder
