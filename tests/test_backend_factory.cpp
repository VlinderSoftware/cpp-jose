#include <catch2/catch_test_macros.hpp>

#include "../src/private/back_end_factory.hpp"
#if defined(JOSE_USE_CNG)
#include "../src/private/cng_back_end.hpp"
#endif
#if defined(JOSE_USE_OPENSSL)
#include "../src/private/openssl_back_end.hpp"
#endif

using namespace std;

using namespace Vlinder::JOSE;
using namespace Vlinder::JOSE::Private;

#if defined(JOSE_USE_OPENSSL)
TEST_CASE("BackendFactoryTest, OpenSSLFactoryCreatesBackend")
{
    auto &factory = BackEndFactory::get();
    auto backend = std::move(factory.createBackEnd());
    REQUIRE(backend);
    auto openssl_backend = dynamic_cast<OpenSSLBackEnd *>(backend.get());
    REQUIRE(openssl_backend != nullptr);
}
#elif defined(JOSE_USE_CNG)
TEST_CASE("BackendFactoryTest, CNGFactoryCreatesBackend")
{
    auto &factory = BackEndFactory::get();
    auto backend = std::move(factory.createBackEnd());
    REQUIRE(backend);
    auto cng_backend = dynamic_cast<CNGBackEnd *>(backend.get());
    REQUIRE(cng_backend != nullptr);
}
#endif
