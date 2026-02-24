#include "jose/crypto_backend_factory.hpp"
#include "cng_backend.cpp"

namespace Vlinder {
namespace JOSE {

class CNGFactory : public CryptoBackendFactory
{
public:
    std::unique_ptr<Details::CryptoBackend> createBackend() const override
    {
        return std::make_unique<Details::CNGBackend>();
    }
};

} // namespace JOSE
} // namespace Vlinder
