#pragma once

#include "back_end_factory.hpp"
#include "openssl_back_end.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

class OpenSSLBackEndFactory : public BackEndFactory
{
public:
    std::unique_ptr<BackEnd> createBackEnd() const override
    {
        return std::make_unique<OpenSSLBackEnd>();
    }
};

} // namespace Private
} // namespace JOSE
} // namespace Vlinder
