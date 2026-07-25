// JWE tests — Phase 3 API (free-function encrypt/decrypt,
// fromCompact/toCompact, fromJSON/toJSON, EncryptAttorney).
//
// RFC references: RFC 7516 (JWE), RFC 7518 §4 (alg), RFC 7518 §5 (enc).
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <map>
#include <span>
#include <stdexcept>
#include <vector>

#include "jose/jose.hpp"

using namespace std;
using namespace Vlinder::JOSE;

// ── Helpers ──────────────────────────────────────────────────────────────────

static int countDots(string const &s)
{
    return static_cast<int>(count(s.begin(), s.end(), '.'));
}

/// The five base64url-encoded members of a compact JWE (RFC 7516 §7.1), split
/// out so a token can be re-serialised as flattened or general JSON with a
/// caller-chosen per-recipient header.
struct CompactParts
{
    string header_;
    string encrypted_key_;
    string iv_;
    string ciphertext_;
    string tag_;
};

static CompactParts splitCompact(string const &compact)
{
    auto const d1 = compact.find('.');
    auto const d2 = compact.find('.', d1 + 1);
    auto const d3 = compact.find('.', d2 + 1);
    auto const d4 = compact.find('.', d3 + 1);
    return CompactParts{compact.substr(0, d1),
                        compact.substr(d1 + 1, d2 - d1 - 1),
                        compact.substr(d2 + 1, d3 - d2 - 1),
                        compact.substr(d3 + 1, d4 - d3 - 1),
                        compact.substr(d4 + 1)};
}

/// Re-serialise @a parts as RFC 7516 §7.2.1 general JSON, with @a header_json
/// (a JSON object literal) as the single recipient's unprotected header.
static string toGeneralJSON(CompactParts const &parts, string const &header_json)
{
    return "{\"protected\":\"" + parts.header_ + "\",\"iv\":\"" + parts.iv_ +
           "\",\"ciphertext\":\"" + parts.ciphertext_ + "\",\"tag\":\"" + parts.tag_ +
           "\",\"recipients\":[{\"header\":" + header_json + ",\"encrypted_key\":\"" +
           parts.encrypted_key_ + "\"}]}";
}

/// Re-serialise @a parts as RFC 7516 §7.2.2 flattened JSON, with @a header_json
/// (a JSON object literal) as the top-level per-recipient unprotected header.
static string toFlattenedJSON(CompactParts const &parts, string const &header_json)
{
    return "{\"protected\":\"" + parts.header_ + "\",\"header\":" + header_json +
           ",\"encrypted_key\":\"" + parts.encrypted_key_ + "\",\"iv\":\"" + parts.iv_ +
           "\",\"ciphertext\":\"" + parts.ciphertext_ + "\",\"tag\":\"" + parts.tag_ + "\"}";
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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              plaintext);

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
                              "payload");

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
                                          plaintext),
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
                                          plaintext),
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
                                          plaintext),
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
                                          plaintext),
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
                                        plaintext));
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
                          plaintext);
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
                              json_payload);

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
                              special);

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
                              large);

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
                               plaintext);
            JWE jwe2 = encrypt(key,
                               JWA::KeyEncryptionAlgorithm::rsa_oaep,
                               JWA::ContentEncryptionAlgorithm::a128gcm,
                               plaintext);

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

SCENARIO("JWE toJSON omits encrypted_key for direct key agreement algorithms",
         "[jwe][json][dir][ecdh][rfc7516][section-7-2]")
{
    GIVEN("a JWE encrypted with dir + A128GCM")
    {
        JWK key = JWK::generateOct(JWK::Use::encryption, 128);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::dir,
                          JWA::ContentEncryptionAlgorithm::a128gcm,
                          string{"direct key payload"});

        WHEN("serialising to flattened JSON")
        {
            string const json_str = jwe.toJSON();

            THEN("'encrypted_key' is absent (RFC 7516 §7.2.2: MUST NOT be present)")
            {
                REQUIRE(json_str.find("\"encrypted_key\"") == string::npos);
            }

            AND_THEN("required envelope fields are present")
            {
                REQUIRE(json_str.find("\"protected\"") != string::npos);
                REQUIRE(json_str.find("\"iv\"") != string::npos);
                REQUIRE(json_str.find("\"ciphertext\"") != string::npos);
                REQUIRE(json_str.find("\"tag\"") != string::npos);
            }

            AND_WHEN("parsing the JSON back and decrypting")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "direct key payload");
                }
            }
        }
    }

    GIVEN("a JWE encrypted with ECDH-ES + A128GCM")
    {
        JWK key = JWK::generateEC(JWK::Use::encryption, "P-256");
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::ecdh_es,
                          JWA::ContentEncryptionAlgorithm::a128gcm,
                          string{"ecdh-es payload"});

        WHEN("serialising to flattened JSON")
        {
            string const json_str = jwe.toJSON();

            THEN("'encrypted_key' is absent (RFC 7516 §7.2.2: MUST NOT be present)")
            {
                REQUIRE(json_str.find("\"encrypted_key\"") == string::npos);
            }

            AND_WHEN("parsing the JSON back and decrypting")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "ecdh-es payload");
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

SCENARIO(
    "JWE toJSON omits encrypted_key per-recipient in general serialisation for dir and ECDH-ES",
    "[jwe][json][dir][ecdh][rfc7516][section-7-2-1]")
{
    // RFC 7516 §7.2.1: "encrypted_key" MUST NOT be present when the
    // encrypted key value is empty.  This test covers the general
    // serialisation path (multi-recipient array) which is distinct from
    // the flattened path tested in the sibling SCENARIO.
    GIVEN("a multi-recipient JWE: one RSA-OAEP recipient and one dir recipient")
    {
        JWK rsa_key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWK oct_key = JWK::generateOct(JWK::Use::encryption, 256);

        // Two separate single-recipient tokens let us extract compact parts for
        // hand-building a general-serialisation envelope.
        JWE rsa_jwe = encrypt(rsa_key,
                              JWA::KeyEncryptionAlgorithm::rsa_oaep,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              string{"general-form dir payload"});
        JWE dir_jwe = encrypt(oct_key,
                              JWA::KeyEncryptionAlgorithm::dir,
                              JWA::ContentEncryptionAlgorithm::a256gcm,
                              string{"general-form dir payload"});

        WHEN("serialising the RSA-OAEP token as flattened JSON")
        {
            string const rsa_json = rsa_jwe.toJSON();
            THEN("'encrypted_key' IS present (non-empty wrapped key)")
            {
                REQUIRE(rsa_json.find("\"encrypted_key\"") != string::npos);
            }
        }

        WHEN("serialising the dir token as flattened JSON")
        {
            string const dir_json = dir_jwe.toJSON();

            THEN("'encrypted_key' is absent (RFC 7516 §7.2.1: MUST NOT be present)")
            {
                REQUIRE(dir_json.find("\"encrypted_key\"") == string::npos);
            }

            AND_WHEN("parsing back and decrypting with the oct key")
            {
                JWE parsed = JWE::fromJSON(dir_json);
                vector<unsigned char> result = decrypt(parsed, oct_key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "general-form dir payload");
                }
            }
        }
    }

    GIVEN("a JWE with ECDH-ES (no wrapped key) serialised as JSON")
    {
        JWK ec_key = JWK::generateEC(JWK::Use::encryption, "P-256");
        JWE jwe = encrypt(ec_key,
                          JWA::KeyEncryptionAlgorithm::ecdh_es,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"ecdh-es general payload"});

        WHEN("serialising to JSON")
        {
            string const json_str = jwe.toJSON();

            THEN("'encrypted_key' is absent (RFC 7516 §7.2.1: MUST NOT be present)")
            {
                REQUIRE(json_str.find("\"encrypted_key\"") == string::npos);
            }

            AND_WHEN("parsing back and decrypting")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, ec_key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "ecdh-es general payload");
                }
            }
        }
    }
}

// ── Multi-recipient (RFC 7516 §7.2 general serialisation) ───────────────────

SCENARIO("JWE fromJSON parses all recipients in RFC 7516 section 7.2 general serialisation",
         "[jwe][json][multi-recipient][rfc7516][section-7-2]")
{
    GIVEN("a compact JWE produced by encrypt() whose encrypted_key is placed second in a "
          "hand-crafted general JSON with a garbage first recipient")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"multi-recipient plaintext"});

        // Decompose compact token into its five base64url parts.
        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        // Build a RFC 7516 §7.2 general serialisation with two recipients:
        //   recipients[0] — garbage encrypted_key (AAAA = 3 zero bytes; will fail RSA-OAEP decrypt)
        //   recipients[1] — the real encrypted_key from the original encrypt()
        string const general_json = "{\"protected\":\"" + hdr_b64 +
                                    "\""
                                    ",\"iv\":\"" +
                                    iv_b64 +
                                    "\""
                                    ",\"ciphertext\":\"" +
                                    ct_b64 +
                                    "\""
                                    ",\"tag\":\"" +
                                    tag_b64 +
                                    "\""
                                    ",\"recipients\":["
                                    "{\"header\":{\"alg\":\"RSA-OAEP\"},\"encrypted_key\":\"AAAA\"}"
                                    ",{\"header\":{\"alg\":\"RSA-OAEP\"},\"encrypted_key\":\"" +
                                    ek_b64 +
                                    "\"}"
                                    "]}";

        WHEN("parsing the general JSON with fromJSON()")
        {
            JWE parsed = JWE::fromJSON(general_json);

            THEN("the protected-header algorithm fields are preserved")
            {
                REQUIRE(parsed.getKeyEncryptionAlgorithm() ==
                        JWA::KeyEncryptionAlgorithm::rsa_oaep);
                REQUIRE(parsed.getContentEncryptionAlgorithm() ==
                        JWA::ContentEncryptionAlgorithm::a256gcm);
            }

            AND_WHEN("decrypting with the matching key (second recipient)")
            {
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("all recipients are tried and plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "multi-recipient plaintext");
                }
            }

            AND_WHEN("re-serialising to JSON")
            {
                string const reserialised = parsed.toJSON();

                THEN("the general-format 'recipients' array is present")
                {
                    REQUIRE(reserialised.find("\"recipients\"") != string::npos);
                }
            }

            AND_WHEN("calling toCompact() on a multi-recipient token")
            {
                THEN("it throws std::runtime_error")
                {
                    REQUIRE_THROWS_AS(parsed.toCompact(), runtime_error);
                }
            }
        }
    }
}

SCENARIO("JWE fromJSON rejects key-wrapping algorithms with no encrypted_key",
         "[jwe][json][validation][rfc7516][section-7-2]")
{
    GIVEN("a JSON JWE with alg=RSA-OAEP but no encrypted_key in either flattened or general form")
    {
        // Produce a valid protected header and ciphertext envelope so that
        // all other validation steps pass; only encrypted_key is absent.
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"payload"});
        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        WHEN("the flattened form has no encrypted_key field")
        {
            // Omit encrypted_key entirely; alg is RSA-OAEP (key-wrapping).
            string const bad_json = "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 +
                                    "\",\"ciphertext\":\"" + ct_b64 + "\",\"tag\":\"" + tag_b64 +
                                    "\"}";

            THEN("fromJSON throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }

            AND_THEN("nothrow overload returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }

        WHEN("the general form has recipients but each recipient is missing encrypted_key")
        {
            string const bad_json = "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 +
                                    "\",\"ciphertext\":\"" + ct_b64 + "\",\"tag\":\"" + tag_b64 +
                                    "\",\"recipients\":[{\"header\":{\"alg\":\"RSA-OAEP\"}}]}";

            THEN("fromJSON throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }
        }
    }
}

SCENARIO("JWE fromJSON rejects an unrecognised alg value in a per-recipient header",
         "[jwe][json][validation][rfc7516][section-7-2]")
{
    GIVEN("a general-serialisation JWE whose recipient header contains an unknown alg string")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"payload"});
        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        // "BOGUS-ALG-999" is not a registered JWA algorithm name.
        string const bad_json = "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 +
                                "\",\"ciphertext\":\"" + ct_b64 + "\",\"tag\":\"" + tag_b64 +
                                "\",\"recipients\":[{\"header\":{\"alg\":\"BOGUS-ALG-999\"},"
                                "\"encrypted_key\":\"" +
                                ek_b64 + "\"}]}";

        WHEN("calling fromJSON() with throwing overload")
        {
            THEN("it throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }
        }

        WHEN("calling fromJSON(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }
    }
}

SCENARIO("JWE fromCompact rejects encrypted_key mismatches against the alg field",
         "[jwe][fromcompact][validation][rfc7518][section-4-5][section-4-6]")
{
    // Build a minimal but structurally valid envelope so all decoding steps
    // before the encrypted_key check succeed.  IV, ciphertext, and tag can
    // be any valid base64url strings.
    string const dummy_iv = Base64URL::encode(vector<unsigned char>(12, 0));
    string const dummy_ct = Base64URL::encode(string("data"));
    string const dummy_tag = Base64URL::encode(vector<unsigned char>(16, 0));

    GIVEN("an RSA-OAEP protected header but an EMPTY encrypted_key part")
    {
        string const hdr_json = R"({"alg":"RSA-OAEP","enc":"A256GCM"})";
        string const hdr_b64 = Base64URL::encode(hdr_json);
        string const compact =
            hdr_b64 + "." + "" + "." + dummy_iv + "." + dummy_ct + "." + dummy_tag;

        WHEN("calling fromCompact() with throwing overload")
        {
            THEN("it throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromCompact(compact), runtime_error);
            }
        }
        WHEN("calling fromCompact(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                auto result = JWE::fromCompact(compact, nothrow);
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("a dir protected header but a NON-EMPTY encrypted_key part")
    {
        string const hdr_json = R"({"alg":"dir","enc":"A128GCM"})";
        string const hdr_b64 = Base64URL::encode(hdr_json);
        string const ek_b64 = Base64URL::encode(string("notempty"));
        string const compact =
            hdr_b64 + "." + ek_b64 + "." + dummy_iv + "." + dummy_ct + "." + dummy_tag;

        WHEN("calling fromCompact() with throwing overload")
        {
            THEN("it throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromCompact(compact), runtime_error);
            }
        }
        WHEN("calling fromCompact(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                auto result = JWE::fromCompact(compact, nothrow);
                REQUIRE_FALSE(result.has_value());
            }
        }
    }

    GIVEN("an ECDH-ES protected header but a NON-EMPTY encrypted_key part")
    {
        string const hdr_json = R"({"alg":"ECDH-ES","enc":"A128GCM"})";
        string const hdr_b64 = Base64URL::encode(hdr_json);
        string const ek_b64 = Base64URL::encode(string("notempty"));
        string const compact =
            hdr_b64 + "." + ek_b64 + "." + dummy_iv + "." + dummy_ct + "." + dummy_tag;

        WHEN("calling fromCompact() with throwing overload")
        {
            THEN("it throws std::runtime_error")
            {
                REQUIRE_THROWS_AS(JWE::fromCompact(compact), runtime_error);
            }
        }
        WHEN("calling fromCompact(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                auto result = JWE::fromCompact(compact, nothrow);
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("JWE decrypt continues past a recipient whose CEK decrypts to garbage",
         "[jwe][decrypt][multi-recipient][rfc7516][section-5-2]")
{
    // RFC 7516 §5.2: a receiver MUST try each recipient until one succeeds,
    // even if CEK unwrap appears to succeed but the resulting CEK fails to
    // authenticate the ciphertext.
    GIVEN("a general-serialisation JWE with recipient[0]=wrong key and recipient[1]=correct key")
    {
        JWK key_a = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWK key_b = JWK::generateRSA(JWK::Use::encryption, 2048);

        string const plaintext = "multi-recipient content-decrypt fallback test";

        // Produce a valid JWE for key_b (correct key).
        JWE jwe_b = encrypt(key_b,
                            JWA::KeyEncryptionAlgorithm::rsa_oaep,
                            JWA::ContentEncryptionAlgorithm::a256gcm,
                            plaintext);
        string const compact_b = jwe_b.toCompact();

        // Extract ciphertext envelope from jwe_b.
        auto const d1 = compact_b.find('.');
        auto const d2 = compact_b.find('.', d1 + 1);
        auto const d3 = compact_b.find('.', d2 + 1);
        auto const d4 = compact_b.find('.', d3 + 1);
        string const hdr_b64 = compact_b.substr(0, d1);
        string const ek_b_b64 = compact_b.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact_b.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact_b.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact_b.substr(d4 + 1);

        // Produce a wrapped key for key_a (wrong CEK for this ciphertext).
        JWE jwe_a = encrypt(key_a,
                            JWA::KeyEncryptionAlgorithm::rsa_oaep,
                            JWA::ContentEncryptionAlgorithm::a256gcm,
                            plaintext);
        string const compact_a = jwe_a.toCompact();
        auto const a_d1 = compact_a.find('.');
        auto const a_d2 = compact_a.find('.', a_d1 + 1);
        string const ek_a_b64 = compact_a.substr(a_d1 + 1, a_d2 - a_d1 - 1);

        // General-serialisation JWE: recipient[0] = key_a's wrapped key (wrong CEK),
        // recipient[1] = key_b's wrapped key (correct CEK).
        string const general_json = "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 +
                                    "\",\"ciphertext\":\"" + ct_b64 + "\",\"tag\":\"" + tag_b64 +
                                    "\",\"recipients\":[{\"encrypted_key\":\"" + ek_a_b64 +
                                    "\"},{\"encrypted_key\":\"" + ek_b_b64 + "\"}]}";

        JWE const jwe = JWE::fromJSON(general_json);

        WHEN("decrypting with key_a (wrong key — produces a bad CEK)")
        {
            THEN("decrypt throws runtime_error (no recipient matched)")
            {
                REQUIRE_THROWS_AS(decrypt(jwe, key_a), runtime_error);
            }
        }

        WHEN("decrypting with key_b (correct key — second recipient)")
        {
            THEN("plaintext is recovered despite recipient[0] failing content decryption")
            {
                vector<unsigned char> result = decrypt(jwe, key_b);
                REQUIRE(string(result.begin(), result.end()) == plaintext);
            }
        }
    }
}

// ── Per-recipient header alg hardening (RFC 7516 §7.2 / security) ────────────

SCENARIO("Per-recipient header alg substitution is rejected at parse time",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // RFC 7516 §7.2: the per-recipient unprotected header is NOT covered by
    // the AAD and can be tampered with.  If an attacker replaces "alg" in a
    // per-recipient header with a DIFFERENT (but recognised) algorithm name,
    // the parser MUST reject the token.
    //
    // Attack modelled here: original protected header has "alg":"RSA-OAEP";
    // attacker substitutes "alg":"RSA1_5" in the per-recipient header.
    // RSA1_5 is a recognised key-wrapping algorithm, so the encrypted_key
    // presence check would not catch this without the explicit alg-consistency
    // check.
    GIVEN("a valid RSA-OAEP JWE compact token reformatted as general JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"attack-me"});

        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        WHEN("the per-recipient header carries a DIFFERENT recognised alg (RSA1_5)")
        {
            // The protected header still says RSA-OAEP; the attacker tampers
            // the per-recipient header's "alg" field to RSA1_5.
            string const bad_json =
                "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 + "\",\"ciphertext\":\"" +
                ct_b64 + "\",\"tag\":\"" + tag_b64 +
                "\",\"recipients\":[{\"header\":{\"alg\":\"RSA1_5\"},\"encrypted_key\":\"" +
                ek_b64 + "\"}]}";

            THEN("fromJSON() (throwing) rejects the token")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }

            AND_THEN("fromJSON(s, nothrow) returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }
    }
}

SCENARIO("Per-recipient header alg matching protected header alg is accepted at parse time",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // Redundant (but harmless) repetition of the protected header's "alg" in
    // a per-recipient header MUST NOT be rejected — it is idempotent.
    // This scenario guards against regression where the new alg-consistency
    // check rejects even matching values.
    GIVEN("a valid RSA-OAEP compact JWE reformatted as general JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"matching-alg-payload"});

        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        WHEN("the per-recipient header repeats the same alg as the protected header (RSA-OAEP)")
        {
            string const json_str =
                "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 + "\",\"ciphertext\":\"" +
                ct_b64 + "\",\"tag\":\"" + tag_b64 +
                "\",\"recipients\":[{\"header\":{\"alg\":\"RSA-OAEP\"},\"encrypted_key\":\"" +
                ek_b64 + "\"}]}";

            THEN("fromJSON() succeeds")
            {
                REQUIRE_NOTHROW(JWE::fromJSON(json_str));
            }

            AND_WHEN("decrypting with the correct key")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "matching-alg-payload");
                }
            }
        }
    }
}

SCENARIO("Per-recipient kid hint is honoured during decryption",
         "[jwe][json][security][kid][rfc7516][section-7-2]")
{
    // RFC 7516 §7.2: per-recipient headers may carry key-identification hints
    // such as "kid".  These are non-security-critical and must remain
    // functional after the alg-hardening change.
    GIVEN("a valid RSA-OAEP compact JWE reformatted as general JSON with a kid in per-recipient "
          "header")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"kid-hint-payload"});

        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        WHEN("the per-recipient header carries only a kid hint (no alg)")
        {
            string const json_str =
                "{\"protected\":\"" + hdr_b64 + "\",\"iv\":\"" + iv_b64 + "\",\"ciphertext\":\"" +
                ct_b64 + "\",\"tag\":\"" + tag_b64 +
                "\",\"recipients\":[{\"header\":{\"kid\":\"my-rsa-key\"},\"encrypted_key\":\"" +
                ek_b64 + "\"}]}";

            THEN("fromJSON() succeeds")
            {
                REQUIRE_NOTHROW(JWE::fromJSON(json_str));
            }

            AND_WHEN("decrypting with the correct key")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "kid-hint-payload");
                }
            }
        }
    }
}

SCENARIO("Flattened JSON per-recipient header alg substitution is rejected at parse time",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // RFC 7516 §7.2 flattened form: the top-level "header" member is the
    // per-recipient unprotected header and is NOT covered by the AAD.
    // An attacker can tamper its "alg" field to downgrade the key-encryption
    // algorithm (e.g. RSA-OAEP → RSA1_5 to enable padding-oracle attacks).
    // The parser MUST reject any token where the per-recipient "header"
    // carries an "alg" that DIFFERS from the protected header's "alg".
    GIVEN("a valid RSA-OAEP compact JWE reformatted as flattened JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"flattened-attack-me"});

        string const compact = jwe.toCompact();
        auto const d1 = compact.find('.');
        auto const d2 = compact.find('.', d1 + 1);
        auto const d3 = compact.find('.', d2 + 1);
        auto const d4 = compact.find('.', d3 + 1);
        string const hdr_b64 = compact.substr(0, d1);
        string const ek_b64 = compact.substr(d1 + 1, d2 - d1 - 1);
        string const iv_b64 = compact.substr(d2 + 1, d3 - d2 - 1);
        string const ct_b64 = compact.substr(d3 + 1, d4 - d3 - 1);
        string const tag_b64 = compact.substr(d4 + 1);

        WHEN("the top-level per-recipient header carries a DIFFERENT recognised alg (RSA1_5)")
        {
            // Flattened form: "header" is at the top level, not inside a
            // "recipients" array.  The attacker tampers "alg" to RSA1_5.
            string const bad_json = "{\"protected\":\"" + hdr_b64 +
                                    "\",\"header\":{\"alg\":\"RSA1_5\"}" + ",\"encrypted_key\":\"" +
                                    ek_b64 + "\",\"iv\":\"" + iv_b64 + "\",\"ciphertext\":\"" +
                                    ct_b64 + "\",\"tag\":\"" + tag_b64 + "\"}";

            THEN("fromJSON() (throwing) rejects the token")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }

            AND_THEN("fromJSON(s, nothrow) returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }
    }
}

// ── alg MUST come from the protected (authenticated) header only ─────────────

SCENARIO("fromJSON rejects a token whose alg is absent from the protected header (flattened form)",
         "[jwe][json][security][rfc7516][section-4-1-1]")
{
    // RFC 7516 §4.1.1 + security requirement: "alg" identifies the key-encryption
    // algorithm and MUST be read exclusively from the JWE Protected Header, which
    // is integrity-protected by the AAD.  If "alg" is absent from the protected
    // header the token MUST be rejected — accepting it would allow an attacker to
    // supply any algorithm via the unauthenticated per-recipient "header", making
    // the per-recipient consistency check tautological.
    GIVEN("a JSON JWE whose protected header has 'enc' but no 'alg', with 'alg' only in the "
          "top-level per-recipient header")
    {
        // Build a protected header that deliberately omits "alg".
        string const prot_json = R"({"enc":"A256GCM"})";
        string const prot_b64 = Base64URL::encode(prot_json);
        string const dummy_iv = Base64URL::encode(vector<unsigned char>(12, 0));
        string const dummy_ct = Base64URL::encode(string("data"));
        string const dummy_tag = Base64URL::encode(vector<unsigned char>(16, 0));

        // "alg" appears ONLY in the unauthenticated per-recipient "header".
        // "AAAA" = 3 zero bytes, non-empty so the encrypted_key presence check
        // for RSA-OAEP does not fire before the alg check.
        string const bad_json =
            "{\"protected\":\"" + prot_b64 + "\",\"header\":{\"alg\":\"RSA-OAEP\"}" +
            ",\"encrypted_key\":\"AAAA\",\"iv\":\"" + dummy_iv + "\",\"ciphertext\":\"" + dummy_ct +
            "\",\"tag\":\"" + dummy_tag + "\"}";

        WHEN("calling fromJSON() with throwing overload")
        {
            THEN("it rejects the token (alg not in protected header)")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }
        }

        WHEN("calling fromJSON(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }
    }
}

SCENARIO("fromJSON rejects a token whose alg is absent from the protected header (general form)",
         "[jwe][json][security][rfc7516][section-4-1-1]")
{
    // Same vulnerability via the general-serialisation ("recipients" array) path.
    // Current code falls back to reading "alg" from the first recipient's
    // per-recipient "header" when absent from "protected"; the resulting kea_opt
    // is set from an unauthenticated source, making subsequent consistency
    // checks tautological.
    GIVEN("a JSON JWE whose protected header has 'enc' but no 'alg', with 'alg' only in a "
          "per-recipient header inside the recipients array")
    {
        string const prot_json = R"({"enc":"A256GCM"})";
        string const prot_b64 = Base64URL::encode(prot_json);
        string const dummy_iv = Base64URL::encode(vector<unsigned char>(12, 0));
        string const dummy_ct = Base64URL::encode(string("data"));
        string const dummy_tag = Base64URL::encode(vector<unsigned char>(16, 0));

        string const bad_json =
            "{\"protected\":\"" + prot_b64 + "\",\"iv\":\"" + dummy_iv + "\",\"ciphertext\":\"" +
            dummy_ct + "\",\"tag\":\"" + dummy_tag +
            "\",\"recipients\":[{\"header\":{\"alg\":\"RSA-OAEP\"},\"encrypted_key\":\"AAAA\"}]}";

        WHEN("calling fromJSON() with throwing overload")
        {
            THEN("it rejects the token (alg not in protected header)")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }
        }

        WHEN("calling fromJSON(s, nothrow)")
        {
            THEN("it returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }
    }
}

// ── Per-recipient header "enc" hardening (RFC 7516 §7.2 / security) ──────────

SCENARIO("Per-recipient header enc substitution is rejected at parse time",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // RFC 7516 §7.2: the per-recipient unprotected header is NOT covered by the
    // AAD.  "enc" selects the content-encryption algorithm, so — exactly like
    // "alg" — a value carried in an unauthenticated header MUST NOT be allowed
    // to disagree with the protected header.  A mismatch indicates tampering
    // and MUST be rejected rather than silently ignored.
    GIVEN("a valid RSA-OAEP / A256GCM JWE reformatted as JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"enc-attack-me"});
        CompactParts const parts = splitCompact(jwe.toCompact());

        WHEN("a recipient header carries a DIFFERENT recognised enc (A128GCM)")
        {
            string const bad_json = toGeneralJSON(parts, R"({"enc":"A128GCM"})");

            THEN("fromJSON() (throwing) rejects the token")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }

            AND_THEN("fromJSON(s, nothrow) returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }

        WHEN("the flattened per-recipient header carries a DIFFERENT recognised enc (A128GCM)")
        {
            string const bad_json = toFlattenedJSON(parts, R"({"enc":"A128GCM"})");

            THEN("fromJSON() (throwing) rejects the token")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }

            AND_THEN("fromJSON(s, nothrow) returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }

        WHEN("a recipient header carries an unrecognised enc")
        {
            string const bad_json = toGeneralJSON(parts, R"({"enc":"BOGUS-ENC"})");

            THEN("fromJSON() reports the unknown value rather than a mismatch")
            {
                REQUIRE_THROWS_WITH(JWE::fromJSON(bad_json),
                                    Catch::Matchers::ContainsSubstring("unknown 'enc' value"));
            }
        }
    }
}

SCENARIO("Per-recipient header enc matching the protected header is accepted",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // Redundant repetition of the protected header's "enc" in a per-recipient
    // header is idempotent and MUST NOT be rejected.  Guards against a
    // regression where the new consistency check rejects matching values.
    GIVEN("a valid RSA-OAEP / A256GCM JWE reformatted as JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"matching-enc-payload"});
        CompactParts const parts = splitCompact(jwe.toCompact());

        WHEN("a recipient header repeats both the protected alg and enc")
        {
            string const json_str = toGeneralJSON(parts, R"({"alg":"RSA-OAEP","enc":"A256GCM"})");

            THEN("fromJSON() succeeds")
            {
                REQUIRE_NOTHROW(JWE::fromJSON(json_str));
            }

            AND_WHEN("decrypting with the correct key")
            {
                JWE parsed = JWE::fromJSON(json_str);
                vector<unsigned char> result = decrypt(parsed, key);

                THEN("plaintext is recovered")
                {
                    REQUIRE(string(result.begin(), result.end()) == "matching-enc-payload");
                }
            }
        }

        WHEN("the flattened per-recipient header repeats the protected enc")
        {
            string const json_str = toFlattenedJSON(parts, R"({"enc":"A256GCM"})");

            THEN("fromJSON() succeeds")
            {
                REQUIRE_NOTHROW(JWE::fromJSON(json_str));
            }
        }
    }
}

// ── Per-recipient header type validation ─────────────────────────────────────

SCENARIO("A per-recipient header whose alg or enc is not a string is rejected",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // A present-but-non-string "alg"/"enc" must not slip past the consistency
    // checks: an is_string() guard alone would skip validation entirely and
    // accept the token, which is the wrong answer for a malformed header.
    GIVEN("a valid RSA-OAEP / A256GCM JWE reformatted as JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"non-string-alg"});
        CompactParts const parts = splitCompact(jwe.toCompact());

        WHEN("a recipient header carries a numeric alg")
        {
            string const bad_json = toGeneralJSON(parts, R"({"alg":5})");

            THEN("fromJSON() rejects the token")
            {
                REQUIRE_THROWS_WITH(JWE::fromJSON(bad_json),
                                    Catch::Matchers::ContainsSubstring("'alg' must be a string"));
            }

            AND_THEN("fromJSON(s, nothrow) returns nullopt")
            {
                REQUIRE_FALSE(JWE::fromJSON(bad_json, nothrow).has_value());
            }
        }

        WHEN("the flattened per-recipient header carries a numeric alg")
        {
            string const bad_json = toFlattenedJSON(parts, R"({"alg":5})");

            THEN("fromJSON() rejects the token")
            {
                REQUIRE_THROWS_AS(JWE::fromJSON(bad_json), runtime_error);
            }
        }

        WHEN("a recipient header carries a non-string enc")
        {
            string const bad_json = toGeneralJSON(parts, R"({"enc":["A256GCM"]})");

            THEN("fromJSON() rejects the token")
            {
                REQUIRE_THROWS_WITH(JWE::fromJSON(bad_json),
                                    Catch::Matchers::ContainsSubstring("'enc' must be a string"));
            }
        }
    }
}

SCENARIO("An unrecognised per-recipient alg is reported as unknown in both JSON forms",
         "[jwe][json][security][rfc7516][section-7-2]")
{
    // The general and flattened paths must agree on how they describe a
    // per-recipient "alg" that names no known algorithm: "unknown value", not
    // "differs from the protected header".
    GIVEN("a valid RSA-OAEP / A256GCM JWE reformatted as JSON")
    {
        JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
        JWE jwe = encrypt(key,
                          JWA::KeyEncryptionAlgorithm::rsa_oaep,
                          JWA::ContentEncryptionAlgorithm::a256gcm,
                          string{"unknown-alg"});
        CompactParts const parts = splitCompact(jwe.toCompact());

        WHEN("a recipient header carries an unrecognised alg")
        {
            string const bad_json = toGeneralJSON(parts, R"({"alg":"BOGUS-ALG"})");

            THEN("fromJSON() reports the unknown value")
            {
                REQUIRE_THROWS_WITH(JWE::fromJSON(bad_json),
                                    Catch::Matchers::ContainsSubstring("unknown 'alg' value"));
            }
        }

        WHEN("the flattened per-recipient header carries an unrecognised alg")
        {
            string const bad_json = toFlattenedJSON(parts, R"({"alg":"BOGUS-ALG"})");

            THEN("fromJSON() reports the unknown value, not a mismatch")
            {
                REQUIRE_THROWS_WITH(JWE::fromJSON(bad_json),
                                    Catch::Matchers::ContainsSubstring("unknown 'alg' value"));
            }
        }
    }
}
