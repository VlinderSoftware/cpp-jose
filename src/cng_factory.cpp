#include "jose/crypto_backend_factory.hpp"
#include "cng_backend.cpp"

namespace Vlinder {
namespace JOSE {

class CNGFactory : public CryptoBackendFactory
{
public:
    std::unique_ptr<CryptoBackend> createBackend() const override
    {
        return std::make_unique<CNGBackend>();
    }
};

} // namespace JOSE
} // namespace Vlinder
