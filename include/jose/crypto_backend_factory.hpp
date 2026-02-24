#pragma once

#include <memory>
#include "details/crypto_backend.hpp"

namespace Vlinder {
namespace JOSE {

class CryptoBackendFactory
{
public:
    virtual ~CryptoBackendFactory() = default;
    virtual std::unique_ptr<Details::CryptoBackend> createBackend() const = 0;
};

} // namespace JOSE
} // namespace Vlinder
