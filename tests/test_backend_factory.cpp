#include <gtest/gtest.h>
#include "details/backend.hpp"
#include "backend_factory.hpp"
#include "openssl_factory.cpp"
#include "cng_factory.cpp"

using namespace Vlinder::JOSE;
using namespace Vlinder::JOSE::Details;

TEST(BackendFactoryTest, OpenSSLFactoryCreatesBackend)
{
    OpenSSLFactory factory;
    auto backend = factory.createBackend();
    ASSERT_NE(backend, nullptr);
    auto openssl_backend = dynamic_cast<OpenSSLBackend *>(backend.get());
    ASSERT_NE(openssl_backend, nullptr);
}

TEST(BackendFactoryTest, CNGFactoryCreatesBackend)
{
    CNGFactory factory;
    auto backend = factory.createBackend();
    ASSERT_NE(backend, nullptr);
    auto cng_backend = dynamic_cast<CNGBackEnd *>(backend.get());
    ASSERT_NE(cng_backend, nullptr);
}
