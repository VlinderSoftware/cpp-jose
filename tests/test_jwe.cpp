// JWE tests — Phase 3 API (free-function encrypt/decrypt,
// fromCompact/toCompact, fromJSON/toJSON, EncryptAttorney).
//
// RFC references: RFC 7516 (JWE), RFC 7518 §4 (alg), RFC 7518 §5 (enc).
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace std;
using namespace Vlinder::JOSE;

// ── Helpers ──────────────────────────────────────────────────────────────────

static int countDots(string const &s)
{
    return static_cast<int>(count(s.begin(), s.end(), '.'));
}

// ── Compact round-trips ───────────────────────────────────────────────────────

SCENARIO("JWE compact round-trip with RSA-OAEP + A128GCM", "[jwe][rsa][compact][rfc7516]")
{
    GIVEN("a 2048-bit RSA encryption key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);

        WHEN("encrypting a plaintext payload")
        {
            string const plaintext = "This is a secret message";
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            THEN("toCompact() returns a 5-part token")
            {
                string compact = jwe.toCompact();
                REQUIRE(countDots(compact) == 4);
            }

            AND_WHEN("decrypting with the same key")
            {
                vector<unsigned char> plainbytes = decrypt(jwe, key);

                THEN("the plaintext matches")
                {
                    string decrypted(plainbytes.begin(), plainbytes.end());
                    REQUIRE(decrypted == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with RSA-OAEP + A256GCM", "[jwe][rsa][compact][rfc7516]")
{
    GIVEN("a 2048-bit RSA encryption key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "Secret data with A256GCM";

        WHEN("encrypting with RSA-OAEP + A256GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with RSA-OAEP-256 + A128GCM", "[jwe][rsa][compact][rfc7516]")
{
    GIVEN("a 2048-bit RSA encryption key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "Testing RSA-OAEP-256";

        WHEN("encrypting with RSA-OAEP-256 + A128GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep_256,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with RSA-OAEP + A128CBC-HS256", "[jwe][rsa][cbc][rfc7516]")
{
    GIVEN("a 2048-bit RSA encryption key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "Testing CBC mode";

        WHEN("encrypting with RSA-OAEP + A128CBC-HS256")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128cbc_hs256,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with RSA-OAEP + A256CBC-HS512", "[jwe][rsa][cbc][rfc7516]")
{
    GIVEN("a 2048-bit RSA encryption key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "Testing A256CBC-HS512";

        WHEN("encrypting with RSA-OAEP + A256CBC-HS512")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a256cbc_hs512,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

// ── AES Key Wrap ──────────────────────────────────────────────────────────────

SCENARIO("JWE compact round-trip with A128KW + A128GCM", "[jwe][aeskw][rfc7516]")
{
    GIVEN("a 128-bit oct encryption key")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 128);
        string const plaintext = "AES Key Wrap test";

        WHEN("encrypting with A128KW + A128GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::a128kw,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with A256KW + A256GCM", "[jwe][aeskw][rfc7516]")
{
    GIVEN("a 256-bit oct encryption key")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 256);
        string const plaintext = "A256KW with A256GCM";

        WHEN("encrypting with A256KW + A256GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::a256kw,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

// ── Direct encryption (dir) ───────────────────────────────────────────────────

SCENARIO("JWE compact round-trip with dir + A128GCM", "[jwe][dir][rfc7516]")
{
    GIVEN("a 128-bit oct encryption key used directly")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 128);
        string const plaintext = "Direct encryption test";

        WHEN("encrypting with dir + A128GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::dir,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

// ── ECDH-ES ───────────────────────────────────────────────────────────────────

SCENARIO("JWE compact round-trip with ECDH-ES + A128GCM (P-256)", "[jwe][ecdh][rfc7516]")
{
    GIVEN("a P-256 EC encryption key")
    {
        JWK key = JWK::generateEC(JWK::Use::encryption, "P-256");
        string const plaintext = "ECDH-ES with A128GCM";

        WHEN("encrypting with ECDH-ES + A128GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::ecdh_es,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            THEN("the token has 5 parts")
            {
                REQUIRE(countDots(jwe.toCompact()) == 4);
            }

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with ECDH-ES + A256GCM (P-256)", "[jwe][ecdh][rfc7516]")
{
    GIVEN("a P-256 EC encryption key")
    {
        JWK key = JWK::generateEC(JWK::Use::encryption, "P-256");
        string const plaintext = "ECDH-ES with A256GCM";

        WHEN("encrypting with ECDH-ES + A256GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::ecdh_es,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with ECDH-ES + A256CBC-HS512 (P-384)", "[jwe][ecdh][cbc][rfc7516]")
{
    GIVEN("a P-384 EC encryption key")
    {
        JWK key = JWK::generateEC(JWK::Use::encryption, "P-384");
        string const plaintext = "ECDH-ES P-384 with A256CBC-HS512";

        WHEN("encrypting with ECDH-ES + A256CBC-HS512")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::ecdh_es,
                              JWA::ContentEncryptionAlgorithm::a256cbc_hs512,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

// ── AES-GCM Key Wrap ──────────────────────────────────────────────────────────

SCENARIO("JWE compact round-trip with A128GCMKW + A128GCM", "[jwe][aesgcmkw][rfc7516]")
{
    GIVEN("a 128-bit oct encryption key")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 128);
        string const plaintext = "A128GCMKW with A128GCM";

        WHEN("encrypting with A128GCMKW + A128GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::a128gcmkw,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with A256GCMKW + A256GCM", "[jwe][aesgcmkw][rfc7516]")
{
    GIVEN("a 256-bit oct encryption key")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 256);
        string const plaintext = "A256GCMKW with A256GCM";

        WHEN("encrypting with A256GCMKW + A256GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::a256gcmkw,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

SCENARIO("JWE compact round-trip with A192GCMKW + A192GCM", "[jwe][aesgcmkw][rfc7516]")
{
    GIVEN("a 192-bit oct encryption key")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 192);
        string const plaintext = "A192GCMKW with A192GCM";

        WHEN("encrypting with A192GCMKW + A192GCM")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::a192gcmkw,
                              JWA::ContentEncryptionAlgorithm::a192gcm,
                              span<char const>{plaintext});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == plaintext);
                }
            }
        }
    }
}

// ── Payload overloads ─────────────────────────────────────────────────────────

SCENARIO("encrypt() accepts vector<unsigned char> payload", "[jwe][overload]")
{
    GIVEN("a 2048-bit RSA key and a binary payload")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        vector<unsigned char> const payload{0x00, 0x01, 0x02, 0xFE, 0xFF};

        WHEN("encrypting the byte vector")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              payload);

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("bytes match")
                {
                    REQUIRE(result == payload);
                }
            }
        }
    }
}

SCENARIO("encrypt() accepts std::string payload", "[jwe][overload]")
{
    GIVEN("a 2048-bit RSA key and a string payload")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const payload = "hello from string overload";

        WHEN("encrypting the string")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              payload);

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("content matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == payload);
                }
            }
        }
    }
}

// ── Type header overload ──────────────────────────────────────────────────────

SCENARIO("encrypt() with type header stores typ in protected header", "[jwe][header][type]")
{
    GIVEN("a 2048-bit RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "typed payload";

        WHEN("encrypting with type='JWE+JSON'")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"JWE+JSON"},
                              span<char const>{plaintext});

            THEN("getType() returns the set type")
            {
                REQUIRE(jwe.getType() == "JWE+JSON");
            }

            AND_THEN("toCompact() encodes it in the header")
            {
                string compact = jwe.toCompact();
                JWE parsed = JWE::fromCompact(compact);
                REQUIRE(parsed.getType() == "JWE+JSON");
            }
        }
    }
}

// ── Key ID and header observers ───────────────────────────────────────────────

SCENARIO("Key ID from the JWK is propagated into the JWE protected header", "[jwe][header][kid]")
{
    GIVEN("an RSA key that carries an auto-generated key ID")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const expected_kid = key.getKeyID();
        REQUIRE_FALSE(expected_kid.empty());

        WHEN("encrypting a payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"kid-test"});

            AND_WHEN("parsing the compact token back")
            {
                JWE parsed = JWE::fromCompact(jwe.toCompact());

                THEN("getKeyID() returns the key's ID")
                {
                    REQUIRE(parsed.getKeyID() == expected_kid);
                }

                AND_THEN("the raw header JSON also contains the kid")
                {
                    REQUIRE(parsed.getHeader().find(expected_kid) != string::npos);
                }
            }
        }
    }
}

SCENARIO("getHeader() returns JSON containing alg and enc fields", "[jwe][header][getheader]")
{
    GIVEN("a JWE produced by encrypt()")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"header-test"});

        WHEN("parsing the compact token and calling getHeader()")
        {
            JWE parsed = JWE::fromCompact(jwe.toCompact());
            string header = parsed.getHeader();

            THEN("the header JSON is non-empty")
            {
                REQUIRE_FALSE(header.empty());
            }

            AND_THEN("it contains the 'alg' field name")
            {
                REQUIRE(header.find("alg") != string::npos);
            }

            AND_THEN("it contains the 'enc' field name")
            {
                REQUIRE(header.find("enc") != string::npos);
            }
        }
    }
}

SCENARIO("Custom header parameters survive a fromCompact round-trip",
         "[jwe][header][custom_params]")
{
    GIVEN("a 2048-bit RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);

        WHEN("encrypting with custom header param 'x-tenant'='acme'")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{""},
                              map<string, string>{{"x-tenant", "acme"}},
                              span<char const>{string{"payload"}});

            AND_WHEN("parsing the compact token back")
            {
                JWE parsed = JWE::fromCompact(jwe.toCompact());
                string header = parsed.getHeader();

                THEN("the custom param name appears in the header")
                {
                    REQUIRE(header.find("x-tenant") != string::npos);
                }

                AND_THEN("the custom param value appears in the header")
                {
                    REQUIRE(header.find("acme") != string::npos);
                }
            }
        }
    }
}

// ── Reserved-name validation ──────────────────────────────────────────────────

SCENARIO("encrypt() rejects reserved header parameter names", "[jwe][header][reserved][rfc7516]")
{
    GIVEN("a 2048-bit RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "test";

        WHEN("passing 'alg' as a custom header parameter")
        {
            THEN("encrypt() throws std::invalid_argument")
            {
                REQUIRE_THROWS_AS(encrypt(key,
                                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                          JWA::ContentEncryptionAlgorithm::a128gcm,
                                          string{""},
                                          map<string, string>{{"alg", "bogus"}},
                                          span<char const>{plaintext}),
                                  invalid_argument);
            }
        }

        WHEN("passing 'enc' as a custom header parameter")
        {
            THEN("encrypt() throws std::invalid_argument")
            {
                REQUIRE_THROWS_AS(encrypt(key,
                                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                          JWA::ContentEncryptionAlgorithm::a128gcm,
                                          string{""},
                                          map<string, string>{{"enc", "bogus"}},
                                          span<char const>{plaintext}),
                                  invalid_argument);
            }
        }

        WHEN("passing 'kid' as a custom header parameter")
        {
            THEN("encrypt() throws std::invalid_argument")
            {
                REQUIRE_THROWS_AS(encrypt(key,
                                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                          JWA::ContentEncryptionAlgorithm::a128gcm,
                                          string{""},
                                          map<string, string>{{"kid", "x"}},
                                          span<char const>{plaintext}),
                                  invalid_argument);
            }
        }

        WHEN("passing 'epk' as a custom header parameter")
        {
            THEN("encrypt() throws std::invalid_argument")
            {
                REQUIRE_THROWS_AS(encrypt(key,
                                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                          JWA::ContentEncryptionAlgorithm::a128gcm,
                                          string{""},
                                          map<string, string>{{"epk", "x"}},
                                          span<char const>{plaintext}),
                                  invalid_argument);
            }
        }

        WHEN("passing a safe custom parameter")
        {
            THEN("encrypt() succeeds")
            {
                REQUIRE_NOTHROW(encrypt(key,
                                        JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                        JWA::ContentEncryptionAlgorithm::a128gcm,
                                        string{""},
                                        map<string, string>{{"x-custom", "value"}},
                                        span<char const>{plaintext}));
            }
        }
    }
}

// ── fromCompact / toCompact ───────────────────────────────────────────────────

SCENARIO("JWE::fromCompact parses a valid token", "[jwe][fromcompact][rfc7516]")
{
    GIVEN("a compact JWE token produced by encrypt()")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE original = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a256gcm,
                               string{"parsed-payload"});
        string compact = original.toCompact();

        WHEN("calling fromCompact() on the token")
        {
            JWE parsed = JWE::fromCompact(compact);

            THEN("the algorithm fields are correct")
            {
                REQUIRE(parsed.getKeyEncryptionAlgorithm() ==
                        JWA::KeyEncryptionAlgorithm::rsa_oaep);
                REQUIRE(parsed.getContentEncryptionAlgorithm() ==
                        JWA::ContentEncryptionAlgorithm::a256gcm);
            }

            AND_THEN("toCompact() reproduces the original token")
            {
                REQUIRE(parsed.toCompact() == compact);
            }

            AND_WHEN("decrypting the parsed JWE")
            {
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == "parsed-payload");
                }
            }
        }
    }
}

SCENARIO("JWE::fromCompact nothrow returns optional<JWE> on success", "[jwe][fromcompact][nothrow]")
{
    GIVEN("a valid compact JWE token")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE original = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               string{"nothrow-test"});
        string compact = original.toCompact();

        WHEN("parsing with the nothrow overload")
        {
            auto result = JWE::fromCompact(compact, nothrow);

            THEN("result has a value")
            {
                REQUIRE(result.has_value());
            }

            AND_THEN("algorithm fields are correct")
            {
                REQUIRE(result->getKeyEncryptionAlgorithm() ==
                        JWA::KeyEncryptionAlgorithm::rsa_oaep);
            }
        }
    }
}

SCENARIO("JWE::fromCompact nothrow returns nullopt for invalid input",
         "[jwe][fromcompact][nothrow]")
{
    GIVEN("strings that are not valid compact JWE tokens")
    {
        WHEN("the input has fewer than 5 parts")
        {
            auto result = JWE::fromCompact("a.b.c.d", nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("the input is empty")
        {
            auto result = JWE::fromCompact("", nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("the header part is not valid base64url")
        {
            auto result = JWE::fromCompact("!!!.b.c.d.e", nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("JWE::fromCompact throwing overload throws on invalid input", "[jwe][fromcompact][throw]")
{
    WHEN("the input has fewer than 5 parts")
    {
        THEN("fromCompact() throws")
        {
            REQUIRE_THROWS(JWE::fromCompact("a.b.c.d"));
        }
    }

    WHEN("the input is empty")
    {
        THEN("fromCompact() throws")
        {
            REQUIRE_THROWS(JWE::fromCompact(""));
        }
    }
}

// ── decrypt(compact, key) convenience overload ───────────────────────────────

SCENARIO("decrypt(compact, key) convenience overload works", "[jwe][decrypt][convenience]")
{
    GIVEN("a compact JWE token")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "convenience decrypt test";
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          span<char const>{plaintext});
        string compact = jwe.toCompact();

        WHEN("decrypting via the compact-string convenience overload")
        {
            vector<unsigned char> result = decrypt(compact, key);

            THEN("plaintext matches")
            {
                REQUIRE(string(result.begin(), result.end()) == plaintext);
            }
        }
    }
}

// ── Wrong-key and tampering failures ─────────────────────────────────────────

SCENARIO("Decrypting with the wrong RSA key fails", "[jwe][security][rsa]")
{
    GIVEN("two different RSA keys")
    {
        JWK key1 = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWK key2 = JWK::generateRSA(JWK::Use::encryption, 2048);

        WHEN("encrypting with key1 and attempting to decrypt with key2")
        {
            JWE jwe = encrypt(key1,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"secret"});

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(jwe, key2));
            }
        }
    }
}

SCENARIO("Decrypting with the wrong AES-KW key fails", "[jwe][security][aeskw]")
{
    GIVEN("two different 256-bit oct keys")
    {
        JWK key1 = JWK::generateOct(JWK::Use::encryption, 256);
        JWK key2 = JWK::generateOct(JWK::Use::encryption, 256);

        WHEN("encrypting with key1 and attempting to decrypt with key2")
        {
            JWE jwe = encrypt(key1,
                              JWA::KeyEncryptionAlgorithm::a256kw,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              string{"secret"});

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(jwe, key2));
            }
        }
    }
}

SCENARIO("Decrypting with the wrong ECDH-ES key fails", "[jwe][security][ecdh]")
{
    GIVEN("two different P-256 EC keys")
    {
        JWK key1 = JWK::generateEC(JWK::Use::encryption, "P-256");
        JWK key2 = JWK::generateEC(JWK::Use::encryption, "P-256");

        WHEN("encrypting with key1 and attempting to decrypt with key2")
        {
            JWE jwe = encrypt(key1,
                              JWA::KeyEncryptionAlgorithm::ecdh_es,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"secret"});

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(jwe, key2));
            }
        }
    }
}

SCENARIO("Tampered ciphertext is rejected", "[jwe][security][tamper]")
{
    GIVEN("a compact JWE token")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a128gcm,
                          string{"original"});
        string compact = jwe.toCompact();

        WHEN("the ciphertext part (4th) is tampered")
        {
            // Locate the 4th dot-delimited segment and flip a character
            size_t d1 = compact.find('.');
            size_t d2 = compact.find('.', d1 + 1);
            size_t d3 = compact.find('.', d2 + 1);
            size_t d4 = compact.find('.', d3 + 1);
            if (d3 != string::npos && d4 != string::npos && d3 + 1 < d4)
            {
                compact[d3 + 1] = (compact[d3 + 1] == 'A') ? 'B' : 'A';
            }

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(compact, key));
            }
        }
    }
}

SCENARIO("Tampered wrapped key in AES-GCM-KW token is rejected",
         "[jwe][security][aesgcmkw][tamper]")
{
    GIVEN("a compact AES-GCM-KW JWE token")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 256);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::a256gcmkw,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"secret content"});
        string compact = jwe.toCompact();

        WHEN("the encrypted-key part (2nd) is tampered")
        {
            size_t d1 = compact.find('.');
            size_t d2 = compact.find('.', d1 + 1);
            if (d1 != string::npos && d2 != string::npos && d1 + 1 < d2)
            {
                compact[d1 + 1] = (compact[d1 + 1] == 'A') ? 'B' : 'A';
            }

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(compact, key));
            }
        }
    }
}

// ── Edge cases ────────────────────────────────────────────────────────────────

SCENARIO("Encrypting an empty payload succeeds and round-trips", "[jwe][edge]")
{
    GIVEN("a 2048-bit RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);

        WHEN("encrypting an empty payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{""});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("result is empty")
                {
                    REQUIRE(result.empty());
                }
            }
        }
    }
}

SCENARIO("Encrypting a JSON document as plaintext round-trips correctly",
         "[jwe][edge][json_payload]")
{
    GIVEN("a 2048-bit RSA key and a JSON-structured payload")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const json_payload =
            R"({"user":"john","role":"admin","permissions":["read","write","delete"]})";

        WHEN("encrypting the JSON payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{json_payload});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("the JSON is recovered byte-for-byte")
                {
                    REQUIRE(string(result.begin(), result.end()) == json_payload);
                }
            }
        }
    }
}

SCENARIO("Encrypting a payload with special characters round-trips correctly",
         "[jwe][edge][special_chars]")
{
    GIVEN("a 2048-bit RSA key and a payload containing newlines, tabs, and symbols")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const special = "Special: \n\t\r\"'{}[]<>!@#$%^&*()";

        WHEN("encrypting the special-character payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{special});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("the special-character payload is recovered exactly")
                {
                    REQUIRE(string(result.begin(), result.end()) == special);
                }
            }
        }
    }
}

SCENARIO("Tampered ciphertext in an ECDH-ES token is rejected", "[jwe][security][ecdh][tamper]")
{
    GIVEN("a compact ECDH-ES + A128GCM JWE token")
    {
        JWK key = JWK::generateEC(JWK::Use::encryption, "P-256");
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::ecdh_es,
                          JWA::ContentEncryptionAlgorithm::a128gcm,
                          string{"original content"});
        string compact = jwe.toCompact();

        WHEN("the ciphertext part (4th) is tampered")
        {
            size_t d1 = compact.find('.');
            size_t d2 = compact.find('.', d1 + 1);
            size_t d3 = compact.find('.', d2 + 1);
            size_t d4 = compact.find('.', d3 + 1);
            if (d3 != string::npos && d4 != string::npos && d3 + 1 < d4)
            {
                compact[d3 + 1] = (compact[d3 + 1] == 'A') ? 'B' : 'A';
            }

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(compact, key));
            }
        }
    }
}

SCENARIO("Decrypting an A128GCMKW token with the wrong key fails", "[jwe][security][aesgcmkw]")
{
    GIVEN("two different 128-bit oct keys")
    {
        JWK key1 = JWK::generateOct(JWK::Use::encryption, 128);
        JWK key2 = JWK::generateOct(JWK::Use::encryption, 128);

        WHEN("encrypting with key1 and attempting to decrypt with key2")
        {
            JWE jwe = encrypt(key1,
                              JWA::KeyEncryptionAlgorithm::a128gcmkw,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"secret"});

            THEN("decrypt() throws")
            {
                REQUIRE_THROWS(decrypt(jwe, key2));
            }
        }
    }
}

SCENARIO("Encrypting a large payload (10 KB) round-trips", "[jwe][edge]")
{
    GIVEN("a 2048-bit RSA key and a 10 KB payload")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const large(10000, 'X');

        WHEN("encrypting the large payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              span<char const>{large});

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("plaintext matches")
                {
                    REQUIRE(string(result.begin(), result.end()) == large);
                }
            }
        }
    }
}

SCENARIO("Encrypting a full binary payload (0..255) round-trips", "[jwe][edge]")
{
    GIVEN("a 2048-bit RSA key and a full-byte-range payload")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        vector<unsigned char> payload(256);
        for (int i = 0; i < 256; ++i)
        {
            payload[static_cast<size_t>(i)] = static_cast<unsigned char>(i);
        }

        WHEN("encrypting the binary payload")
        {
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              payload);

            AND_WHEN("decrypting")
            {
                vector<unsigned char> result = decrypt(jwe, key);

                THEN("bytes match exactly")
                {
                    REQUIRE(result == payload);
                }
            }
        }
    }
}

SCENARIO("Encrypting the same plaintext twice produces different tokens", "[jwe][probabilistic]")
{
    GIVEN("a 2048-bit RSA key")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        string const plaintext = "same plaintext";

        WHEN("encrypting the payload twice")
        {
            JWE jwe1 = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               span<char const>{plaintext});
            JWE jwe2 = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               span<char const>{plaintext});

            THEN("the compact tokens differ (probabilistic encryption)")
            {
                REQUIRE(jwe1.toCompact() != jwe2.toCompact());
            }

            AND_THEN("both decrypt to the same plaintext")
            {
                auto r1 = decrypt(jwe1, key);
                auto r2 = decrypt(jwe2, key);
                REQUIRE(string(r1.begin(), r1.end()) == plaintext);
                REQUIRE(string(r2.begin(), r2.end()) == plaintext);
            }
        }
    }
}

// ── Copy / move semantics ─────────────────────────────────────────────────────

SCENARIO("JWE copy/move semantics", "[jwe][value_semantics]")
{
    GIVEN("a JWE produced by encrypt()")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE original = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               string{"value semantics test"});
        string compact = original.toCompact();

        WHEN("copy-constructing from the original")
        {
            JWE copy(original);
            THEN("copy.toCompact() equals original.toCompact()")
            {
                REQUIRE(copy.toCompact() == compact);
            }
        }

        WHEN("copy-assigning from the original")
        {
            JWE assigned = original;
            THEN("assigned.toCompact() equals original.toCompact()")
            {
                REQUIRE(assigned.toCompact() == compact);
            }
        }

        WHEN("move-constructing from the original")
        {
            JWE moved(std::move(original));
            THEN("moved.toCompact() equals the expected compact token")
            {
                REQUIRE(moved.toCompact() == compact);
            }
        }

        WHEN("move-assigning from the original")
        {
            JWE moved = std::move(original);
            THEN("moved.toCompact() equals the expected compact token")
            {
                REQUIRE(moved.toCompact() == compact);
            }
        }
    }
}

// ── fromJSON / toJSON (RFC 7516 §7.2) ────────────────────────────────────────

SCENARIO("JWE toJSON produces valid RFC 7516 section 7.2 flattened JSON", "[jwe][json][rfc7516]")
{
    GIVEN("a JWE produced by encrypt()")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"json serialisation test"});

        WHEN("serialising to JSON form")
        {
            string json_str = jwe.toJSON();

            THEN("the JSON contains required RFC 7516 §7.2 fields")
            {
                REQUIRE(json_str.find("\"protected\"") != string::npos);
                REQUIRE(json_str.find("\"encrypted_key\"") != string::npos);
                REQUIRE(json_str.find("\"iv\"") != string::npos);
                REQUIRE(json_str.find("\"ciphertext\"") != string::npos);
                REQUIRE(json_str.find("\"tag\"") != string::npos);
            }

            AND_WHEN("parsing the JSON back with fromJSON()")
            {
                JWE parsed = JWE::fromJSON(json_str);

                THEN("algorithm fields are preserved")
                {
                    REQUIRE(parsed.getKeyEncryptionAlgorithm() ==
                            JWA::KeyEncryptionAlgorithm::rsa_oaep);
                    REQUIRE(parsed.getContentEncryptionAlgorithm() ==
                            JWA::ContentEncryptionAlgorithm::a256gcm);
                }

                AND_WHEN("decrypting the parsed JWE")
                {
                    vector<unsigned char> result = decrypt(parsed, key);

                    THEN("plaintext is recovered")
                    {
                        REQUIRE(string(result.begin(), result.end()) == "json serialisation test");
                    }
                }
            }
        }
    }
}

SCENARIO("JWE::fromJSON nothrow returns optional<JWE> on success", "[jwe][json][nothrow][rfc7516]")
{
    GIVEN("a valid RFC 7516 §7.2 JSON JWE")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a128gcm,
                          string{"nothrow json test"});
        string json_str = jwe.toJSON();

        WHEN("parsing with the nothrow overload")
        {
            auto result = JWE::fromJSON(json_str, nothrow);

            THEN("result has a value")
            {
                REQUIRE(result.has_value());
            }
        }
    }
}

SCENARIO("JWE::fromJSON nothrow returns nullopt for invalid input", "[jwe][json][nothrow][rfc7516]")
{
    GIVEN("strings that are not valid RFC 7516 §7.2 JSON JWE objects")
    {
        WHEN("the input is empty")
        {
            auto result = JWE::fromJSON("", nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("the input is plain JSON but missing required fields")
        {
            auto result = JWE::fromJSON("{\"foo\":\"bar\"}", nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("the input is a compact token (not JSON)")
        {
            JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
            JWE jwe = encrypt(key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a128gcm,
                              string{"payload"});
            auto result = JWE::fromJSON(jwe.toCompact(), nothrow);
            THEN("result is empty")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}
