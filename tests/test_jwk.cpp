#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>
#include <string>

#include "jose/jose.hpp"

#if defined(JOSE_USE_OPENSSL)
#include <openssl/core_names.h>
#include <openssl/evp.h>
#endif

using namespace std;

using namespace Vlinder::JOSE;

namespace {

// Stable RFC 7520 Section 3.4 RSA private key fixture used for import-shape tests.
string const k_rsa_private_json_fixture = R"({
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB",
    "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNt_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
    "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
    "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
    "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
    "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
    "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
})";

}  // namespace

#if defined(JOSE_USE_OPENSSL)
namespace {

void appendDerLength(vector<unsigned char> &out, size_t length)
{
    if (length < 0x80)
    {
        out.push_back(static_cast<unsigned char>(length));
        return;
    }

    unsigned char encoded[sizeof(size_t)] = {};
    size_t count = 0;
    size_t value = length;
    while (value != 0)
    {
        encoded[count++] = static_cast<unsigned char>(value & 0xFF);
        value >>= 8;
    }

    out.push_back(static_cast<unsigned char>(0x80 | count));
    for (size_t i = 0; i < count; ++i)
    {
        out.push_back(encoded[count - 1 - i]);
    }
}

void appendDerInteger(vector<unsigned char> &out, vector<unsigned char> const &value)
{
    vector<unsigned char> normalized = value;
    while (normalized.size() > 1 && normalized[0] == 0)
    {
        normalized.erase(normalized.begin());
    }

    if (normalized.empty())
    {
        normalized.push_back(0);
    }

    if ((normalized[0] & 0x80) != 0)
    {
        normalized.insert(normalized.begin(), 0);
    }

    out.push_back(0x02);
    appendDerLength(out, normalized.size());
    out.insert(out.end(), normalized.begin(), normalized.end());
}

vector<unsigned char> buildRSAPrivateKeyPKCS1DERFromJSON(nlohmann::json const &json)
{
    auto n = Base64Url::decode(json.at("n").get<string>());
    auto e = Base64Url::decode(json.at("e").get<string>());
    auto d = Base64Url::decode(json.at("d").get<string>());
    auto p = Base64Url::decode(json.at("p").get<string>());
    auto q = Base64Url::decode(json.at("q").get<string>());
    auto dp = Base64Url::decode(json.at("dp").get<string>());
    auto dq = Base64Url::decode(json.at("dq").get<string>());
    auto qi = Base64Url::decode(json.at("qi").get<string>());

    vector<unsigned char> body;
    appendDerInteger(body, vector<unsigned char>{0});
    appendDerInteger(body, n);
    appendDerInteger(body, e);
    appendDerInteger(body, d);
    appendDerInteger(body, p);
    appendDerInteger(body, q);
    appendDerInteger(body, dp);
    appendDerInteger(body, dq);
    appendDerInteger(body, qi);

    vector<unsigned char> der;
    der.push_back(0x30);
    appendDerLength(der, body.size());
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

vector<unsigned char> bnToBytes(BIGNUM *bn)
{
    if (bn == nullptr)
    {
        return {};
    }

    int n = BN_num_bytes(bn);
    vector<unsigned char> out(static_cast<size_t>(n));
    BN_bn2bin(bn, out.data());
    return out;
}

}  // namespace
#endif

// BDD-style tests for RSA key generation
SCENARIO("RSA keys can be generated with different bit sizes", "[jwk][rsa][generation][bdd]")
{
    GIVEN("no specific requirements")
    {
        WHEN("generating a default RSA key")
        {
            JWK key = JWK::generateRSA(JWK::Use::signature);

            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 2048-bit RSA")
    {
        WHEN("generating a 2048-bit RSA key")
        {
            JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 3072-bit RSA")
    {
        WHEN("generating a 3072-bit RSA key")
        {
            JWK key = JWK::generateRSA(JWK::Use::signature, 3072);

            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 4096-bit RSA")
    {
        WHEN("generating a 4096-bit RSA key")
        {
            JWK key = JWK::generateRSA(JWK::Use::signature, 4096);

            THEN("it should be an RSA key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

TEST_CASE("Generated RSA keys always serialize full private CRT material", "[jwk][rsa][generation]")
{
    for (int i = 0; i < 32; ++i)
    {
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
        nlohmann::json json = nlohmann::json::parse(key.toJSON(true));

        REQUIRE(json.contains("d"));
        REQUIRE(json.contains("p"));
        REQUIRE(json.contains("q"));
        REQUIRE(json.contains("dp"));
        REQUIRE(json.contains("dq"));
        REQUIRE(json.contains("qi"));
    }
}

// BDD-style tests for EC key generation
SCENARIO("Elliptic curve keys can be generated with different curves", "[jwk][ec][generation][bdd]")
{
    GIVEN("no specific curve requirement")
    {
        WHEN("generating a default EC key")
        {
            JWK key = JWK::generateEC(JWK::Use::signature);

            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for P-256 curve")
    {
        WHEN("generating a P-256 EC key")
        {
            JWK key = JWK::generateEC(JWK::Use::signature, "P-256");

            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for P-384 curve")
    {
        WHEN("generating a P-384 EC key")
        {
            JWK key = JWK::generateEC(JWK::Use::signature, "P-384");

            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for P-521 curve")
    {
        WHEN("generating a P-521 EC key")
        {
            JWK key = JWK::generateEC(JWK::Use::signature, "P-521");

            THEN("it should be an EC key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::ec);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

// BDD-style tests for symmetric key generation
SCENARIO("Symmetric keys can be generated with different bit sizes", "[jwk][oct][generation][bdd]")
{
    GIVEN("no specific requirements")
    {
        WHEN("generating a default symmetric key")
        {
            JWK key = JWK::generateOct(JWK::Use::signature);

            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 128-bit key")
    {
        WHEN("generating a 128-bit symmetric key")
        {
            JWK key = JWK::generateOct(JWK::Use::signature, 128);

            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 192-bit key")
    {
        WHEN("generating a 192-bit symmetric key")
        {
            JWK key = JWK::generateOct(JWK::Use::signature, 192);

            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }

    GIVEN("a requirement for 256-bit key")
    {
        WHEN("generating a 256-bit symmetric key")
        {
            JWK key = JWK::generateOct(JWK::Use::signature, 256);

            THEN("it should be an octet key with a private component")
            {
                REQUIRE(key.getKeyType() == JWK::KeyType::oct);
                REQUIRE(key.hasPrivateKey());
            }
        }
    }
}

// BDD-style tests for key properties
SCENARIO("JWK properties can be set and retrieved", "[jwk][properties][bdd]")
{
    GIVEN("a generated RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

        WHEN("setting a key ID")
        {
            key.setKeyID("my-key-id");

            THEN("the key ID can be retrieved")
            {
                REQUIRE(key.getKeyID() == "my-key-id");
            }
        }

        WHEN("setting a key ID with special characters")
        {
            key.setKeyID("key-2024-01-01-v1.0");

            THEN("the special characters are preserved")
            {
                REQUIRE(key.getKeyID() == "key-2024-01-01-v1.0");
            }
        }

        WHEN("setting an algorithm")
        {
            key.setAlgorithm("RS256");

            THEN("the algorithm can be retrieved")
            {
                REQUIRE(key.getAlgorithm() == "RS256");
            }
        }

        WHEN("setting the use to signature")
        {
            THEN("it should not throw")
            {
                REQUIRE_NOTHROW(key.setUse(JWK::Use::signature));
            }
        }

        WHEN("setting the use to encryption")
        {
            THEN("it should not throw")
            {
                REQUIRE_NOTHROW(key.setUse(JWK::Use::encryption));
            }
        }
    }
}

TEST_CASE("Different key types support different algorithms", "[jwk][properties]")
{
    JWK rsaKey = JWK::generateRSA(JWK::Use::signature, 2048);
    rsaKey.setAlgorithm("RS512");
    REQUIRE(rsaKey.getAlgorithm() == "RS512");

    JWK ecKey = JWK::generateEC(JWK::Use::signature, "P-256");
    ecKey.setAlgorithm("ES256");
    REQUIRE(ecKey.getAlgorithm() == "ES256");

    JWK octKey = JWK::generateOct(JWK::Use::signature, 256);
    octKey.setAlgorithm("HS256");
    REQUIRE(octKey.getAlgorithm() == "HS256");
}

// BDD-style serialization tests
SCENARIO("JWKs can be serialized to JSON", "[jwk][serialization][bdd]")
{
    GIVEN("an RSA key with metadata")
    {
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
        key.setKeyID("rsa-key-1");
        key.setAlgorithm("RS256");

        WHEN("serializing with private key")
        {
            string json = key.toJSON(true);

            THEN("the JSON should contain all key components")
            {
                REQUIRE(json.find("\"kty\"") != string::npos);
                REQUIRE(json.find("\"RSA\"") != string::npos);
                REQUIRE(json.find("\"kid\"") != string::npos);
                REQUIRE(json.find("\"rsa-key-1\"") != string::npos);
                REQUIRE(json.find("\"alg\"") != string::npos);
                REQUIRE(json.find("\"RS256\"") != string::npos);
            }
        }

        WHEN("serializing without private key")
        {
            key.setKeyID("rsa-public-key");
            string json = key.toJSON(false);

            THEN("the JSON should contain only public components")
            {
                REQUIRE(json.find("\"kty\"") != string::npos);
                REQUIRE(json.find("\"RSA\"") != string::npos);
                REQUIRE(json.find("\"kid\"") != string::npos);
            }
        }
    }

    GIVEN("an EC key with metadata")
    {
        JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
        key.setKeyID("ec-key-1");
        key.setAlgorithm("ES256");

        WHEN("serializing with private key")
        {
            string json = key.toJSON(true);

            THEN("the JSON should contain curve information")
            {
                REQUIRE(json.find("\"kty\"") != string::npos);
                REQUIRE(json.find("\"EC\"") != string::npos);
                REQUIRE(json.find("\"crv\"") != string::npos);
                REQUIRE(json.find("\"P-256\"") != string::npos);
            }
        }
    }

    GIVEN("a symmetric key")
    {
        JWK key = JWK::generateOct(JWK::Use::signature, 256);
        key.setKeyID("symmetric-key");
        key.setAlgorithm("HS256");

        WHEN("serializing the key")
        {
            string json = key.toJSON(true);

            THEN("the JSON should contain the key material")
            {
                REQUIRE(json.find("\"kty\"") != string::npos);
                REQUIRE(json.find("\"oct\"") != string::npos);
                REQUIRE(json.find("\"k\"") != string::npos);
            }
        }
    }
}

// BDD-style parsing tests
SCENARIO("JWKs can be parsed from JSON", "[jwk][parsing][bdd]")
{
    GIVEN("a serialized RSA key")
    {
        JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
        original.setKeyID("test-rsa");
        string json = original.toJSON(true);

        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);

            THEN("the key should be reconstructed correctly")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(parsed.getKeyID() == "test-rsa");

                bool const has_serialized_private =
                    json.find("\"d\"") != string::npos && json.find("\"p\"") != string::npos &&
                    json.find("\"q\"") != string::npos && json.find("\"dp\"") != string::npos &&
                    json.find("\"dq\"") != string::npos && json.find("\"qi\"") != string::npos;
                REQUIRE(parsed.hasPrivateKey() == has_serialized_private);
            }
        }
    }

    GIVEN("a serialized EC key")
    {
        JWK original = JWK::generateEC(JWK::Use::signature, "P-384");
        original.setKeyID("test-ec");
        original.setAlgorithm("ES384");
        string json = original.toJSON(true);

        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);

            THEN("the key should be reconstructed with all metadata")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::ec);
                REQUIRE(parsed.getKeyID() == "test-ec");
                REQUIRE(parsed.getAlgorithm() == "ES384");
            }
        }
    }

    GIVEN("a serialized symmetric key")
    {
        JWK original = JWK::generateOct(JWK::Use::signature, 256);
        original.setKeyID("test-oct");
        string json = original.toJSON(true);

        WHEN("parsing the JSON")
        {
            JWK parsed = JWK::fromJSON(json);

            THEN("the key should be reconstructed")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::oct);
                REQUIRE(parsed.getKeyID() == "test-oct");
            }
        }
    }

    GIVEN("a public key only JSON")
    {
        JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
        original.setKeyID("public-only");
        string publicJson = original.toJSON(false);

        WHEN("parsing the public key JSON")
        {
            JWK parsed = JWK::fromJSON(publicJson);

            THEN("the key should not have a private component")
            {
                REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
                REQUIRE(parsed.getKeyID() == "public-only");
                REQUIRE_FALSE(parsed.hasPrivateKey());
            }
        }
    }
}

// Round-trip tests
TEST_CASE("JWK RSA round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("rsa-round-trip");
    original.setAlgorithm("RS256");
    original.setUse(JWK::Use::signature);

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());

    bool const has_serialized_private =
        json.find("\"d\"") != string::npos && json.find("\"p\"") != string::npos &&
        json.find("\"q\"") != string::npos && json.find("\"dp\"") != string::npos &&
        json.find("\"dq\"") != string::npos && json.find("\"qi\"") != string::npos;
    REQUIRE(parsed.hasPrivateKey() == has_serialized_private);
}

#if defined(JOSE_USE_OPENSSL)
TEST_CASE("JWK RSA private JSON reconstructs to importable PKCS#1 DER", "[jwk][rsa][openssl][der]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    auto json = nlohmann::json::parse(original.toJSON(true));

    vector<unsigned char> der = buildRSAPrivateKeyPKCS1DERFromJSON(json);
    REQUIRE_FALSE(der.empty());

    unsigned char const *der_ptr = der.data();
    auto pkey = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(
        d2i_AutoPrivateKey(nullptr, &der_ptr, static_cast<long>(der.size())),
        EVP_PKEY_free);
    REQUIRE(pkey != nullptr);

    BIGNUM *n_bn = nullptr;
    BIGNUM *e_bn = nullptr;
    REQUIRE(EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, &n_bn) == 1);
    REQUIRE(EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, &e_bn) == 1);

    auto n_guard = unique_ptr<BIGNUM, decltype(&BN_free)>(n_bn, BN_free);
    auto e_guard = unique_ptr<BIGNUM, decltype(&BN_free)>(e_bn, BN_free);

    REQUIRE(bnToBytes(n_guard.get()) == Base64Url::decode(json["n"].get<string>()));
    REQUIRE(bnToBytes(e_guard.get()) == Base64Url::decode(json["e"].get<string>()));
}
#endif

TEST_CASE("OpenSSL RSA private round-trip avoids legacy fallback across 1024 runs",
          "[jwk][rsa][openssl][stress][.]")
{
    for (int i = 0; i < 1024; ++i)
    {
        JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
        string json = original.toJSON(true);
        JWK parsed = JWK::fromJSON(json);
        REQUIRE(parsed.hasPrivateKey());
    }
}

TEST_CASE("JWK RSA import rejects missing qi", "[jwk][rsa][round-trip][openssl][strict]")
{
    nlohmann::json json = nlohmann::json::parse(k_rsa_private_json_fixture);

    json.erase("qi");

    REQUIRE_THROWS_WITH(JWK::fromJSON(json.dump()),
                        Catch::Matchers::ContainsSubstring("Ill-formed RSA private key"));
}

TEST_CASE("JWK RSA import rejects missing CRT exponents", "[jwk][rsa][round-trip][openssl][strict]")
{
    nlohmann::json json = nlohmann::json::parse(k_rsa_private_json_fixture);

    json.erase("dp");
    json.erase("dq");
    json.erase("qi");

    REQUIRE_THROWS_WITH(JWK::fromJSON(json.dump()),
                        Catch::Matchers::ContainsSubstring("Ill-formed RSA private key"));
}

TEST_CASE("JWK RSA import rejects incomplete private parameters",
          "[jwk][rsa][round-trip][openssl][strict]")
{
    nlohmann::json json = nlohmann::json::parse(k_rsa_private_json_fixture);

    json.erase("p");

    REQUIRE_THROWS_WITH(JWK::fromJSON(json.dump()),
                        Catch::Matchers::ContainsSubstring("Ill-formed RSA private key"));
}

TEST_CASE("JWK RSA import accepts private key with n/e/d only",
          "[jwk][rsa][round-trip][openssl][strict]")
{
    nlohmann::json json = nlohmann::json::parse(k_rsa_private_json_fixture);

    json.erase("p");
    json.erase("q");
    json.erase("dp");
    json.erase("dq");
    json.erase("qi");

#if defined(JOSE_USE_CNG)
    REQUIRE_THROWS_WITH(
        JWK::fromJSON(json.dump()),
        Catch::Matchers::ContainsSubstring(
            "CNG RSA import requires either a public key (n, e) or a full private key"));
#else
    JWK parsed = JWK::fromJSON(json.dump());
    REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
    REQUIRE(parsed.hasPrivateKey());
#endif
}

TEST_CASE("JWK RSA import rejects d without n/e", "[jwk][rsa][round-trip][strict]")
{
    nlohmann::json json = {
        {"kty", "RSA"},
        {"use", "sig"},
        {"alg", "RS256"},
        {"d", "AQAB"},
    };

    REQUIRE_THROWS_WITH(JWK::fromJSON(json.dump()),
                        Catch::Matchers::ContainsSubstring("Missing required RSA parameters"));
}

TEST_CASE("JWK EC round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateEC(JWK::Use::signature, "P-521");
    original.setKeyID("ec-round-trip");
    original.setAlgorithm("ES512");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());
}

TEST_CASE("JWK Oct round-trip preserves all properties", "[jwk][round-trip]")
{
    JWK original = JWK::generateOct(JWK::Use::signature, 256);
    original.setKeyID("oct-round-trip");
    original.setAlgorithm("HS256");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(original.getKeyType() == parsed.getKeyType());
    REQUIRE(original.getKeyID() == parsed.getKeyID());
    REQUIRE(original.getAlgorithm() == parsed.getAlgorithm());
}

TEST_CASE("JWK RSA fromJSON can ignore private parameters", "[jwk][rsa][parsing]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("rsa-ignore-private");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json, true);

    REQUIRE(parsed.getKeyType() == JWK::KeyType::rsa);
    REQUIRE(parsed.getKeyID() == "rsa-ignore-private");
    REQUIRE_FALSE(parsed.hasPrivateKey());

    nlohmann::json parsed_json = nlohmann::json::parse(parsed.toJSON(true));
    REQUIRE_FALSE(parsed_json.contains("d"));
    REQUIRE_FALSE(parsed_json.contains("p"));
    REQUIRE_FALSE(parsed_json.contains("q"));
    REQUIRE_FALSE(parsed_json.contains("dp"));
    REQUIRE_FALSE(parsed_json.contains("dq"));
    REQUIRE_FALSE(parsed_json.contains("qi"));
}

TEST_CASE("JWK EC fromJSON can ignore private parameters", "[jwk][ec][parsing]")
{
    JWK original = JWK::generateEC(JWK::Use::signature, "P-256");
    original.setKeyID("ec-ignore-private");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json, true);

    REQUIRE(parsed.getKeyType() == JWK::KeyType::ec);
    REQUIRE(parsed.getKeyID() == "ec-ignore-private");
    REQUIRE_FALSE(parsed.hasPrivateKey());

    nlohmann::json parsed_json = nlohmann::json::parse(parsed.toJSON(true));
    REQUIRE_FALSE(parsed_json.contains("d"));
}

TEST_CASE("JWK Oct fromJSON can ignore private parameters", "[jwk][oct][parsing]")
{
    JWK original = JWK::generateOct(JWK::Use::signature, 256);
    original.setKeyID("oct-ignore-private");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json, true);

    REQUIRE(parsed.getKeyType() == JWK::KeyType::oct);
    REQUIRE(parsed.getKeyID() == "oct-ignore-private");
    REQUIRE_FALSE(parsed.hasPrivateKey());

    nlohmann::json parsed_json = nlohmann::json::parse(parsed.toJSON(true));
    REQUIRE_FALSE(parsed_json.contains("k"));
}

#if defined(JOSE_USE_OPENSSL)
TEST_CASE("JWK OKP signature key generation works", "[jwk][okp][openssl]")
{
    JWK key = JWK::generateOKP(JWK::Use::signature);
    REQUIRE(key.getKeyType() == JWK::KeyType::okp);
    REQUIRE(key.hasPrivateKey());

    key.setAlgorithm("EdDSA");
    string json = key.toJSON(true);
    REQUIRE(json.find("\"kty\":\"OKP\"") != string::npos);
    REQUIRE(json.find("\"crv\":\"Ed25519\"") != string::npos);
    REQUIRE(json.find("\"x\"") != string::npos);
    REQUIRE(json.find("\"d\"") != string::npos);
}

TEST_CASE("JWK OKP encryption key generation works", "[jwk][okp][openssl]")
{
    JWK key = JWK::generateOKP(JWK::Use::encryption, 448, "ECDH-ES");
    REQUIRE(key.getKeyType() == JWK::KeyType::okp);
    REQUIRE(key.hasPrivateKey());

    string json = key.toJSON(false);
    REQUIRE(json.find("\"crv\":\"X448\"") != string::npos);
    REQUIRE(json.find("\"x\"") != string::npos);
    REQUIRE(json.find("\"d\"") == string::npos);
}

TEST_CASE("JWK OKP round-trip preserves key material", "[jwk][okp][openssl][round-trip]")
{
    JWK original = JWK::generateOKP(JWK::Use::signature, 255, "EdDSA");
    original.setKeyID("okp-rt");

    string private_json = original.toJSON(true);
    JWK parsed_private = JWK::fromJSON(private_json);
    REQUIRE(parsed_private.getKeyType() == JWK::KeyType::okp);
    REQUIRE(parsed_private.hasPrivateKey());
    REQUIRE(parsed_private.getKeyID() == "okp-rt");

    string public_json = original.toJSON(false);
    JWK parsed_public = JWK::fromJSON(public_json);
    REQUIRE(parsed_public.getKeyType() == JWK::KeyType::okp);
    REQUIRE_FALSE(parsed_public.hasPrivateKey());
}

TEST_CASE("JWK OKP fromJSON can ignore private parameters", "[jwk][okp][openssl][parsing]")
{
    JWK original = JWK::generateOKP(JWK::Use::signature, 255, "EdDSA");
    original.setKeyID("okp-ignore-private");

    string json = original.toJSON(true);
    JWK parsed = JWK::fromJSON(json, true);

    REQUIRE(parsed.getKeyType() == JWK::KeyType::okp);
    REQUIRE(parsed.getKeyID() == "okp-ignore-private");
    REQUIRE_FALSE(parsed.hasPrivateKey());

    nlohmann::json parsed_json = nlohmann::json::parse(parsed.toJSON(true));
    REQUIRE_FALSE(parsed_json.contains("d"));
}
#endif

// Copy and move semantics
TEST_CASE("JWK copy constructor works correctly", "[jwk][copy]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");

    JWK copy(original);
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK copy assignment works correctly", "[jwk][copy]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");

    JWK copy = original;
    REQUIRE(original.getKeyID() == copy.getKeyID());
    REQUIRE(original.getKeyType() == copy.getKeyType());
}

TEST_CASE("JWK move constructor works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");
    string expectedId = original.getKeyID();

    JWK moved(std::move(original));
    REQUIRE(expectedId == moved.getKeyID());
}

TEST_CASE("JWK move assignment works correctly", "[jwk][move]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    original.setKeyID("original");
    string expectedId = original.getKeyID();

    JWK moved = std::move(original);
    REQUIRE(expectedId == moved.getKeyID());
}
