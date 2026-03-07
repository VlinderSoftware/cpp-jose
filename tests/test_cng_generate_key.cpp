#ifdef _WIN32
#include <catch2/catch_test_macros.hpp>

#include "../src/private/cng_back_end.hpp"

using namespace std;

using namespace Vlinder::JOSE::Private;

TEST_CASE("CNGBackEnd generate RSA and EC keys")
{
    CNGBackEnd backend;

    SECTION("generate RSA 2048")
    {
        auto key = backend.generateRSA(2048);
        REQUIRE(key != nullptr);
        CNGRSAKey *rsa = dynamic_cast<CNGRSAKey *>(key.get());
        REQUIRE(rsa != nullptr);
        auto n = rsa->getN();
        auto e = rsa->getE();
        REQUIRE(!n.empty());
        REQUIRE(!e.empty());
        REQUIRE(rsa->hasPrivate());
    }

    SECTION("generate EC P-256")
    {
        auto key = backend.generateEC("P-256");
        REQUIRE(key != nullptr);
        CNGECKey *ec = dynamic_cast<CNGECKey *>(key.get());
        REQUIRE(ec != nullptr);
        auto pub = ec->getPublicBlob();
        REQUIRE(!pub.empty());
        REQUIRE(ec->hasPrivate());
    }
}
#endif
