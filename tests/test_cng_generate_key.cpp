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
        auto [key_opt, key_err] = backend.generateRSA(2048);
        REQUIRE(key_opt.has_value());
        auto &key = *key_opt;
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
        auto [key_opt, key_err] = backend.generateEC("P-256");
        REQUIRE(key_opt.has_value());
        auto &key = *key_opt;
        CNGECKey *ec = dynamic_cast<CNGECKey *>(key.get());
        REQUIRE(ec != nullptr);
        auto pub = ec->getPublicBlob();
        REQUIRE(!pub.empty());
        REQUIRE(ec->hasPrivate());
    }
}
#endif
