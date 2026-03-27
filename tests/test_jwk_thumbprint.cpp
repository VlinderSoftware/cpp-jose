#include <catch2/catch_test_macros.hpp>
#include <set>
#include <sstream>
#include <string>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

// Basic thumbprint computation tests
TEST_CASE("ComputeRSAThumbprint", "[jwa][computersathumbprint]")
{
    auto key = JWK::generateRSA(JWK::Use::signature, 2048);
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    // Base64URL encoded SHA-256 is 43 characters (256 bits / 6 bits per char, rounded up)
    REQUIRE(43 == thumbprint.length());
}

TEST_CASE("ComputeECThumbprint", "[jwa][computeecthumbprint]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    REQUIRE(43 == thumbprint.length());
}

TEST_CASE("ComputeOctThumbprint", "[jwa][computeoctthumbprint]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    REQUIRE(43 == thumbprint.length());
}

// Default algorithm is SHA-256
TEST_CASE("DefaultAlgorithmIsSHA256", "[jwa][defaultalgorithmissha256]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    auto thumbprint1 = JWKThumbprint::compute(key);
    auto thumbprint2 = JWKThumbprint::compute(key, "SHA-256");

    REQUIRE(thumbprint1 == thumbprint2);
}

// Different hash algorithms
TEST_CASE("ComputeWithSHA384", "[jwa][computewithsha384]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string thumbprint = JWKThumbprint::compute(key, "SHA-384").get();

    REQUIRE_FALSE(thumbprint.empty());
    // SHA-384 produces 384 bits = 64 base64url characters
    REQUIRE(64 == thumbprint.length());
}

TEST_CASE("ComputeWithSHA512", "[jwa][computewithsha512]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string thumbprint = JWKThumbprint::compute(key, "SHA-512").get();

    REQUIRE_FALSE(thumbprint.empty());
    // SHA-512 produces 512 bits = 86 base64url characters
    REQUIRE(86 == thumbprint.length());
}

// Deterministic thumbprints
TEST_CASE("ThumbprintIsDeterministic", "[jwa][thumbprintisdeterministic]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    auto thumbprint1 = JWKThumbprint::compute(key);
    auto thumbprint2 = JWKThumbprint::compute(key);

    REQUIRE(thumbprint1 == thumbprint2);
}

TEST_CASE("SameKeyDifferentPropertiesSameThumbprint",
          "[jwa][samekeydifferentpropertiessamethumbprint]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    string keyJson = key1.toJSON(true);

    JWK key2 = JWK::fromJSON(keyJson);
    key2.setKeyID("different-id");
    key2.setAlgorithm("RS512");
    key2.setUse(JWK::Use::signature);

    // Thumbprint should be the same because it's based on key material only
    JWKThumbprint thumbprint1 = JWKThumbprint::compute(key1);
    JWKThumbprint thumbprint2 = JWKThumbprint::compute(key2);

    REQUIRE(thumbprint1 == thumbprint2);
}

// Different keys produce different thumbprints
TEST_CASE("DifferentKeysProduceDifferentThumbprints",
          "[jwa][differentkeysproducedifferentthumbprints]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);

    JWKThumbprint thumbprint1 = JWKThumbprint::compute(key1);
    JWKThumbprint thumbprint2 = JWKThumbprint::compute(key2);

    REQUIRE(thumbprint1 != thumbprint2);
}

TEST_CASE("DifferentKeyTypesProduceDifferentThumbprints",
          "[jwa][differentkeytypesproducedifferentthumbprints]")
{
    JWK rsaKey = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK ecKey = JWK::generateEC(JWK::Use::signature, "P-256");
    JWK octKey = JWK::generateOct(JWK::Use::signature, 256);

    JWKThumbprint rsaThumbprint = JWKThumbprint::compute(rsaKey);
    JWKThumbprint ecThumbprint = JWKThumbprint::compute(ecKey);
    JWKThumbprint octThumbprint = JWKThumbprint::compute(octKey);

    REQUIRE(rsaThumbprint != ecThumbprint);
    REQUIRE(rsaThumbprint != octThumbprint);
    REQUIRE(ecThumbprint != octThumbprint);
}

// Test with different EC curves
TEST_CASE("DifferentECCurvesProduceDifferentThumbprints",
          "[jwa][differenteccurvesproducedifferentthumbprints]")
{
    JWK keyP256 = JWK::generateEC(JWK::Use::signature, "P-256");
    JWK keyP384 = JWK::generateEC(JWK::Use::signature, "P-384");
    JWK keyP521 = JWK::generateEC(JWK::Use::signature, "P-521");

    JWKThumbprint thumbprintP256 = JWKThumbprint::compute(keyP256);
    JWKThumbprint thumbprintP384 = JWKThumbprint::compute(keyP384);
    JWKThumbprint thumbprintP521 = JWKThumbprint::compute(keyP521);

    REQUIRE(thumbprintP256 != thumbprintP384);
    REQUIRE(thumbprintP256 != thumbprintP521);
    REQUIRE(thumbprintP384 != thumbprintP521);
}

// Raw thumbprint tests
TEST_CASE("ComputeRawThumbprint", "[jwa][computerawthumbprint]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    auto rawThumbprint = JWKThumbprint::compute(key).getRaw();

    REQUIRE_FALSE(rawThumbprint.empty());
    // SHA-256 produces 32 bytes
    REQUIRE(32 == rawThumbprint.size());
}

TEST_CASE("ComputeRawThumbprintSHA384", "[jwa][computerawthumbprintsha384]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    auto rawThumbprint = JWKThumbprint::compute(key, "SHA-384").getRaw();

    REQUIRE_FALSE(rawThumbprint.empty());
    // SHA-384 produces 48 bytes
    REQUIRE(48 == rawThumbprint.size());
}

TEST_CASE("ComputeRawThumbprintSHA512", "[jwa][computerawthumbprintsha512]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    auto rawThumbprint = JWKThumbprint::compute(key, "SHA-512").getRaw();

    REQUIRE_FALSE(rawThumbprint.empty());
    // SHA-512 produces 64 bytes
    REQUIRE(64 == rawThumbprint.size());
}

TEST_CASE("RawThumbprintMatchesEncodedThumbprint", "[jwa][rawthumbprintmatchesencodedthumbprint]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    string encoded = JWKThumbprint::compute(key).get();
    auto raw = JWKThumbprint::compute(key).getRaw();

    // Encode the raw thumbprint and compare
    string encodedFromRaw = Base64URL::encode(raw);

    REQUIRE(encoded == encodedFromRaw);
}

// Round-trip tests
TEST_CASE("ThumbprintSurvivesSerializationRoundTrip",
          "[jwa][thumbprintsurvivesserializationroundtrip]")
{
    JWK original = JWK::generateRSA(JWK::Use::signature, 2048);
    JWKThumbprint originalThumbprint = JWKThumbprint::compute(original);

    // Serialize and deserialize
    string json = original.toJSON(true);
    JWK deserialized = JWK::fromJSON(json);

    JWKThumbprint deserializedThumbprint = JWKThumbprint::compute(deserialized);

    REQUIRE(originalThumbprint == deserializedThumbprint);
}

TEST_CASE("PublicKeyOnlyThumbprintMatchesFullKey", "[jwa][publickeyonlythumbprintmatchesfullkey]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);
    JWKThumbprint privateThumbprint = JWKThumbprint::compute(privateKey);

    // Export public key only
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    JWKThumbprint publicThumbprint = JWKThumbprint::compute(publicKey);

    // Thumbprint should be the same
    REQUIRE(privateThumbprint == publicThumbprint);
}

// Test that thumbprint doesn't contain invalid base64url characters
TEST_CASE("ThumbprintIsValidBase64Url", "[jwa][thumbprintisvalidbase64url]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWKThumbprint thumbprint = JWKThumbprint::compute(key);

    // Should not contain '+', '/', or '='
    REQUIRE(string::npos == thumbprint.get().find('+'));
    REQUIRE(string::npos == thumbprint.get().find('/'));
    REQUIRE(string::npos == thumbprint.get().find('='));

    // Should only contain valid base64url characters: A-Z, a-z, 0-9, -, _
    for (char c : thumbprint.get())
    {
        bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                     c == '-' || c == '_';
        REQUIRE(valid);
    }
}

// Edge cases
TEST_CASE("SmallKeyThumbprint", "[jwa][smallkeythumbprint]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 128);
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    REQUIRE(43 == thumbprint.length());
}

TEST_CASE("LargeKeyThumbprint", "[jwa][largekeythumbprint]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 4096);
    string thumbprint = JWKThumbprint::compute(key).get();

    // Thumbprint size should be the same regardless of key size
    REQUIRE(43 == thumbprint.length());
}

// RFC 7638 compliance test
TEST_CASE("RFC7638Example", "[jwa][rfc7638example]")
{
    // RFC 7638 Section 3.1 provides an example
    // We can't test the exact example without the exact key, but we can test the format
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    string thumbprint = JWKThumbprint::compute(key).get();

    // Verify it's a valid base64url string of the right length for SHA-256
    REQUIRE(43 == thumbprint.length());

    // Verify it's deterministic
    string thumbprint2 = JWKThumbprint::compute(key).get();
    REQUIRE(thumbprint == thumbprint2);
}

// Test all key types
TEST_CASE("AllKeyTypesProduceValidThumbprints", "[jwa][allkeytypesproducevalidthumbprints]")
{
    vector<JWK> keys = {JWK::generateRSA(JWK::Use::signature, 2048),
                        JWK::generateEC(JWK::Use::signature, "P-256"),
                        JWK::generateEC(JWK::Use::signature, "P-384"),
                        JWK::generateEC(JWK::Use::signature, "P-521"),
                        JWK::generateOct(JWK::Use::signature, 128),
                        JWK::generateOct(JWK::Use::signature, 256),
                        JWK::generateOct(JWK::Use::signature, 512)};

    for (auto const &key : keys)
    {
        string thumbprint = JWKThumbprint::compute(key).get();
        REQUIRE_FALSE(thumbprint.empty());
        REQUIRE(43 == thumbprint.length());

        // Verify it's base64url
        REQUIRE(string::npos == thumbprint.find('+'));
        REQUIRE(string::npos == thumbprint.find('/'));
        REQUIRE(string::npos == thumbprint.find('='));
    }
}

// Test with different hash algorithms for all key types
TEST_CASE("AllHashAlgorithmsWork", "[jwa][allhashalgorithmswork]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    vector<pair<string, size_t>> algorithms = {{"SHA-256", 43}, {"SHA-384", 64}, {"SHA-512", 86}};

    for (auto const &[alg, expectedLength] : algorithms)
    {
        string thumbprint = JWKThumbprint::compute(key, alg).get();
        REQUIRE_FALSE(thumbprint.empty());
        REQUIRE(expectedLength == thumbprint.length());
    }
}

// Use thumbprint as key ID
TEST_CASE("UseThumbprintAsKeyId", "[jwa][usethumbprintaskeyid]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    string thumbprint = JWKThumbprint::compute(key).get();
    key.setKeyID(thumbprint);

    REQUIRE(thumbprint == key.getKeyID());

    // Verify it survives serialization
    string json = key.toJSON(false);
    JWK parsed = JWK::fromJSON(json);

    REQUIRE(thumbprint == parsed.getKeyID());

    // Verify the thumbprint of the parsed key is still the same
    string parsedThumbprint = JWKThumbprint::compute(parsed).get();
    REQUIRE(thumbprint == parsedThumbprint);
}

TEST_CASE("GeneratedKeyDefaultsKidToThumbprint", "[jwa][defaultkid]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    string const thumbprint = JWKThumbprint::compute(key).get();
    REQUIRE(key.getKeyID() == thumbprint);

    string const json = key.toJSON(false);
    REQUIRE(json.find("\"kid\":\"") != string::npos);
    REQUIRE(json.find(thumbprint) != string::npos);
}

TEST_CASE("ParsedKeyWithoutKidDefaultsToThumbprint", "[jwa][defaultkid]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    key.setKeyID("");
    string const json = key.toJSON(false);

    JWK parsed = JWK::fromJSON(json);

    REQUIRE(parsed.getKeyID() == JWKThumbprint::compute(parsed).get());
}

// Uniqueness test
TEST_CASE("ManyKeysProduceUniqueThumbprints", "[jwa][manykeysproduceuniquethumbprints]")
{
    set<string> thumbprints;

    // Generate 100 keys and verify all thumbprints are unique
    for (int i = 0; i < 100; i++)
    {
        JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
        string thumbprint = JWKThumbprint::compute(key).get();

        REQUIRE(0 == thumbprints.count(thumbprint));
        thumbprints.insert(thumbprint);
    }

    REQUIRE(100 == thumbprints.size());
}

// RFC 7638 Section 3.1 known-answer test
TEST_CASE("RFC7638KnownAnswerTest", "[jwa][rfc7638knownanswertest]")
{
    // Key and expected thumbprint taken verbatim from RFC 7638 Section 3.1
    string const key_json =
        R"({"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"})";

    JWK key = JWK::fromJSON(key_json);
    string thumbprint = JWKThumbprint::compute(key).get();

    // Expected value from RFC 7638 Section 3.1
    REQUIRE("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" == thumbprint);
}

// OKP (Ed25519 / X25519) thumbprint tests
#if JOSE_USE_OPENSSL
TEST_CASE("ComputeOKPEd25519Thumbprint", "[jwa][computeokped25519thumbprint]")
{
    JWK key = JWK::generateOKP(JWK::Use::signature);
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    REQUIRE(43 == thumbprint.length());
}

TEST_CASE("ComputeOKPX25519Thumbprint", "[jwa][computeokpx25519thumbprint]")
{
    JWK key = JWK::generateOKP(JWK::Use::encryption);
    string thumbprint = JWKThumbprint::compute(key).get();

    REQUIRE_FALSE(thumbprint.empty());
    REQUIRE(43 == thumbprint.length());
}

TEST_CASE("OKPPrivateKeyThumbprintMatchesPublicKey",
          "[jwa][okpprivatekeythumbprintmatchespublickey]")
{
    JWK private_key = JWK::generateOKP(JWK::Use::signature);
    JWKThumbprint private_thumbprint = JWKThumbprint::compute(private_key);

    string public_key_json = private_key.toJSON(false);
    JWK public_key = JWK::fromJSON(public_key_json);
    JWKThumbprint public_thumbprint = JWKThumbprint::compute(public_key);

    REQUIRE(private_thumbprint == public_thumbprint);
}
#endif

// Comparison operator tests
TEST_CASE("SameKeyThumbprintOrderingOperators", "[jwa][samekeythumbprintorderingoperators]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWKThumbprint tp1 = JWKThumbprint::compute(key);
    JWKThumbprint tp2 = JWKThumbprint::compute(key);

    REQUIRE(tp1 == tp2);
    REQUIRE_FALSE(tp1 != tp2);
    REQUIRE(tp1 <= tp2);
    REQUIRE(tp1 >= tp2);
    REQUIRE_FALSE(tp1 < tp2);
    REQUIRE_FALSE(tp1 > tp2);
}

TEST_CASE("DifferentKeyThumbprintOrderingConsistency",
          "[jwa][differentkeythumbprintorderingconsistency]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);

    JWKThumbprint tp1 = JWKThumbprint::compute(key1);
    JWKThumbprint tp2 = JWKThumbprint::compute(key2);

    // Two different thumbprints must satisfy strict weak ordering
    if (tp1 < tp2)
    {
        REQUIRE(tp2 > tp1);
        REQUIRE(tp1 <= tp2);
        REQUIRE(tp2 >= tp1);
        REQUIRE_FALSE(tp1 > tp2);
        REQUIRE_FALSE(tp2 < tp1);
        REQUIRE_FALSE(tp1 >= tp2);
        REQUIRE_FALSE(tp2 <= tp1);
        REQUIRE(tp1 != tp2);
        REQUIRE_FALSE(tp1 == tp2);
    }
    else
    {
        // tp2 < tp1 (a SHA-256 collision is computationally infeasible)
        REQUIRE(tp2 < tp1);
        REQUIRE(tp1 > tp2);
        REQUIRE(tp2 <= tp1);
        REQUIRE(tp1 >= tp2);
        REQUIRE(tp1 != tp2);
        REQUIRE_FALSE(tp1 == tp2);
    }
}

// Stream output operator test
TEST_CASE("ThumbprintStreamOutput", "[jwa][thumbprintstreamoutput]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWKThumbprint thumbprint = JWKThumbprint::compute(key);

    ostringstream oss;
    oss << thumbprint;

    REQUIRE(thumbprint.get() == oss.str());
    REQUIRE_FALSE(oss.str().empty());
    REQUIRE(43 == oss.str().length());
}

// Invalid / unsupported hash algorithm throws
TEST_CASE("InvalidAlgorithmThrows", "[jwa][invalidalgorithmthrows]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    REQUIRE_THROWS(JWKThumbprint::compute(key, "MD5"));
    REQUIRE_THROWS(JWKThumbprint::compute(key, "SHA-1"));
    REQUIRE_THROWS(JWKThumbprint::compute(key, "BLAKE2b"));
    REQUIRE_THROWS(JWKThumbprint::compute(key, ""));
}
