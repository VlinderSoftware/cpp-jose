#include "backend_factory.hpp"
#include "openssl_backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

class OpenSSLFactory : public BackendFactory
{
public:
    std::unique_ptr<Details::Backend> createBackend() const override
    {
        return std::make_unique<Details::OpenSSLBackend>();
    }
};

}  // namespace Private
} // namespace JOSE
} // namespace Vlinder
