#include "jose/crypto_backend_factory.hpp"
#include "openssl_backend.cpp"

namespace Vlinder {
namespace JOSE {

class OpenSSLFactory : public CryptoBackendFactory
{
public:
    std::unique_ptr<Details::CryptoBackend> createBackend() const override
    {
        return std::make_unique<Details::OpenSSLBackend>();
    }
};

} // namespace JOSE
} // namespace Vlinder
