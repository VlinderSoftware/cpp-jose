#include <catch2/catch_test_macros.hpp>
#include <string>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

// Basic JWS creation tests
TEST_CASE("JWS_CreateSimpleJWS", "[jws][createsimplejws]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("test payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);
    REQUIRE_FALSE(token.empty());

    // Should have 3 parts separated by dots
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    REQUIRE(string::npos != firstDot);
    REQUIRE(string::npos != secondDot);
}

TEST_CASE("JWS_CreateJWSWithAllAlgorithms", "[jws][createjwswithallalgorithms]")
{
    vector<pair<JWA::SignatureAlgorithm, JWK>> testCases = {
        {JWA::SignatureAlgorithm::hs256, JWK::generateOct(JWK::Use::signature, 256)},
        {JWA::SignatureAlgorithm::hs384, JWK::generateOct(JWK::Use::signature, 384)},
        {JWA::SignatureAlgorithm::hs512, JWK::generateOct(JWK::Use::signature, 512)},
        {JWA::SignatureAlgorithm::rs256, JWK::generateRSA(JWK::Use::signature, 2048)},
        {JWA::SignatureAlgorithm::rs384, JWK::generateRSA(JWK::Use::signature, 2048)},
        {JWA::SignatureAlgorithm::rs512, JWK::generateRSA(JWK::Use::signature, 2048)},
        {JWA::SignatureAlgorithm::es256, JWK::generateEC(JWK::Use::signature, "P-256")},
        {JWA::SignatureAlgorithm::es384, JWK::generateEC(JWK::Use::signature, "P-384")},
        {JWA::SignatureAlgorithm::es512, JWK::generateEC(JWK::Use::signature, "P-521")},
        {JWA::SignatureAlgorithm::ps256, JWK::generateRSA(JWK::Use::signature, 2048)},
        {JWA::SignatureAlgorithm::ps384, JWK::generateRSA(JWK::Use::signature, 2048)},
        {JWA::SignatureAlgorithm::ps512, JWK::generateRSA(JWK::Use::signature, 2048)}};

    for (auto const &[alg, key] : testCases)
    {
        JWS jws;
        jws.setPayload("test");
        jws.setAlgorithm(alg);

        string token = jws.sign(key);
        REQUIRE_FALSE(token.empty());
    }
}

TEST_CASE("JWS_SetPayload", "[jws][setpayload]")
{
    JWS jws;
    jws.setPayload("Hello, World!");

    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);
    JWS parsed = JWS::parse(token);

    REQUIRE(parsed.getPayload() == "Hello, World!");
}

TEST_CASE("JWS_SetKeyId", "[jws][setkeyid]")
{
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setKeyID("my-key-123");

    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    string header = parsed.getHeader();

    REQUIRE(string::npos != header.find("my-key-123"));
}

TEST_CASE("JWS_SetType", "[jws][settype]")
{
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setType("JWT");

    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    string header = parsed.getHeader();

    REQUIRE(string::npos != header.find("JWT"));
}

TEST_CASE("JWS_SetCustomHeaderParam", "[jws][setcustomheaderparam]")
{
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setHeaderParam("custom", "value");

    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    string header = parsed.getHeader();

    REQUIRE(string::npos != header.find("custom"));
    REQUIRE(string::npos != header.find("value"));
}

TEST_CASE("JWS_GetHeader", "[jws][getheader]")
{
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setKeyID("key-1");
    jws.setType("JWT");

    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    string header = parsed.getHeader();

    REQUIRE_FALSE(header.empty());
    REQUIRE(string::npos != header.find("alg"));
    REQUIRE(string::npos != header.find("HS256"));
}

TEST_CASE("JWS_GetAlgorithm", "[jws][getalgorithm]")
{
    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::rs256);

    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    REQUIRE(JWA::SignatureAlgorithm::rs256 == parsed.getAlgorithm());
}

// Verification tests
TEST_CASE("JWS_VerifyValidHS256", "[jws][verifyvalidhs256]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("secure message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);

    bool verified = JWS::verify(token, key);
    REQUIRE(verified);
}

TEST_CASE("JWS_VerifyValidRS256", "[jws][verifyvalidrs256]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    JWS jws;
    jws.setPayload("rsa signed message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::rs256);

    string token = jws.sign(key);

    bool verified = JWS::verify(token, key);
    REQUIRE(verified);
}

TEST_CASE("JWS_VerifyValidES256", "[jws][verifyvalides256]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");

    JWS jws;
    jws.setPayload("ecdsa signed message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::es256);

    string token = jws.sign(key);

    bool verified = JWS::verify(token, key);
    REQUIRE(verified);
}

TEST_CASE("JWS_VerifyWithWrongKeyFails", "[jws][verifywithwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(JWK::Use::signature, 256);
    JWK key2 = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key1);

    bool verified = JWS::verify(token, key2);
    REQUIRE_FALSE(verified);
}

TEST_CASE("JWS_VerifyTamperedPayloadFails", "[jws][verifytamperedpayloadfails]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("original payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);

    // Tamper with token by modifying the payload part
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot != string::npos && secondDot != string::npos)
    {
        token[firstDot + 1] = (token[firstDot + 1] == 'A') ? 'B' : 'A';
    }

    bool verified = JWS::verify(token, key);
    REQUIRE_FALSE(verified);
}

TEST_CASE("JWS_VerifyTamperedSignatureFails", "[jws][verifytamperedsignaturefails]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("payload");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);

    // Tamper with signature
    size_t lastDot = token.rfind('.');
    if (lastDot != string::npos && lastDot + 1 < token.length())
    {
        token[lastDot + 1] = (token[lastDot + 1] == 'A') ? 'B' : 'A';
    }

    bool verified = JWS::verify(token, key);
    REQUIRE_FALSE(verified);
}

// Parsing tests
TEST_CASE("JWS_ParseJWS", "[jws][parsejws]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    original.setKeyID("key-123");

    string token = original.sign(key);

    JWS parsed = JWS::parse(token);
    REQUIRE("test payload" == parsed.getPayload());
    REQUIRE(JWA::SignatureAlgorithm::hs256 == parsed.getAlgorithm());
}

TEST_CASE("JWS_ParseAndGetPayload", "[jws][parseandgetpayload]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);

    JWS jws;
    jws.setPayload("This is the payload content");
    jws.setAlgorithm(JWA::SignatureAlgorithm::rs256);

    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    REQUIRE("This is the payload content" == parsed.getPayload());
}

// Copy and move semantics
TEST_CASE("JWS_CopyConstructor", "[jws][copyconstructor]")
{
    JWS original;
    original.setPayload("test");
    original.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    JWS copy(original);
    REQUIRE(original.getPayload() == copy.getPayload());
    REQUIRE(original.getAlgorithm() == copy.getAlgorithm());
}

TEST_CASE("JWS_CopyAssignment", "[jws][copyassignment]")
{
    JWS original;
    original.setPayload("test");
    original.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    JWS copy = original;
    REQUIRE(original.getPayload() == copy.getPayload());
}

TEST_CASE("JWS_MoveConstructor", "[jws][moveconstructor]")
{
    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    JWS moved(std::move(original));
    REQUIRE("test payload" == moved.getPayload());
}

TEST_CASE("JWS_MoveAssignment", "[jws][moveassignment]")
{
    JWS original;
    original.setPayload("test payload");
    original.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    JWS moved = std::move(original);
    REQUIRE("test payload" == moved.getPayload());
}

// Edge cases
TEST_CASE("JWS_EmptyPayload", "[jws][emptypayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);
    REQUIRE_FALSE(token.empty());

    bool verified = JWS::verify(token, key);
    REQUIRE(verified);
}

TEST_CASE("JWS_LargePayload", "[jws][largepayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    string largePayload(10000, 'X');

    JWS jws;
    jws.setPayload(largePayload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);
    REQUIRE_FALSE(token.empty());

    JWS parsed = JWS::parse(token);
    REQUIRE(largePayload == parsed.getPayload());
}

TEST_CASE("JWS_PayloadWithSpecialCharacters", "[jws][payloadwithspecialcharacters]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    string payload = "Special chars: \n\t\r\"'{}[]";

    JWS jws;
    jws.setPayload(payload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    REQUIRE(payload == parsed.getPayload());
}

TEST_CASE("JWS_JSONPayload", "[jws][jsonpayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    string jsonPayload = R"({"name":"John","age":30,"city":"New York"})";

    JWS jws;
    jws.setPayload(jsonPayload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);

    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    REQUIRE(jsonPayload == parsed.getPayload());
}

TEST_CASE("JWS_MultipleHeaderParams", "[jws][multipleheaderparams]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    jws.setPayload("test");
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setKeyID("key-1");
    jws.setType("JWT");
    jws.setHeaderParam("custom1", "value1");
    jws.setHeaderParam("custom2", "value2");

    string token = jws.sign(key);

    JWS parsed = JWS::parse(token);
    string header = parsed.getHeader();

    REQUIRE(string::npos != header.find("custom1"));
    REQUIRE(string::npos != header.find("custom2"));
}

// Public key verification
TEST_CASE("JWS_JWS_RSAPublicKeyVerification", "[jws][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);

    JWS jws;
    jws.setPayload("message for public verification");
    jws.setAlgorithm(JWA::SignatureAlgorithm::rs256);

    string token = jws.sign(privateKey);

    // Extract public key
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    bool verified = JWS::verify(token, publicKey);
    REQUIRE(verified);
}

TEST_CASE("JWS_ECPublicKeyVerification", "[jws][ecpublickeyverification]")
{
    JWK privateKey = JWK::generateEC(JWK::Use::signature, "P-256");

    JWS jws;
    jws.setPayload("ec message");
    jws.setAlgorithm(JWA::SignatureAlgorithm::es256);

    string token = jws.sign(privateKey);

    // Extract public key
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    bool verified = JWS::verify(token, publicKey);
    REQUIRE(verified);
}

// Interoperability test
TEST_CASE("JWS_CreateWithJWSVerifyWithJWT", "[jws][createwithjwsverifywithjwt]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    JWS jws;
    string payload = R"({"sub":"1234567890","name":"John Doe","iat":1516239022})";
    jws.setPayload(payload);
    jws.setAlgorithm(JWA::SignatureAlgorithm::hs256);
    jws.setType("JWT");

    string token = jws.sign(key);

    // Should be verifiable as JWT
    bool verified = JWS::verify(token, key);
    REQUIRE(verified);
}

// ─── Wrong-key failure tests for asymmetric algorithms ───────────────────────

TEST_CASE("JWS_VerifyWithWrongECKeyFails", "[jws][verifywithwrongeckeyfails]")
{
    JWK key1 = JWK::generateEC(JWK::Use::signature, "P-256");
    JWK key2 = JWK::generateEC(JWK::Use::signature, "P-256");

    JWS jws;
    jws.setPayload("signed with key1");
    jws.setAlgorithm(JWA::SignatureAlgorithm::es256);

    string token = jws.sign(key1);

    bool result = JWS::verify(token, key2);
    REQUIRE_FALSE(result);
}

TEST_CASE("JWS_VerifyWithWrongRSAKeyFails", "[jws][verifywithwrongrsakkeyfails]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);

    JWS jws;
    jws.setPayload("signed with rsa key1");
    jws.setAlgorithm(JWA::SignatureAlgorithm::rs256);

    string token = jws.sign(key1);

    bool result = JWS::verify(token, key2);
    REQUIRE_FALSE(result);
}

TEST_CASE("JWS_VerifyWithWrongPSSKeyFails", "[jws][verifywithwrongpsskeyfails]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);

    JWS jws;
    jws.setPayload("signed with pss key1");
    jws.setAlgorithm(JWA::SignatureAlgorithm::ps256);

    string token = jws.sign(key1);

    bool result = JWS::verify(token, key2);
    REQUIRE_FALSE(result);
}

TEST_CASE("JWS_VerifyES256PublicKeyOnlySucceeds", "[jws][verifyes256publickeyonlysucceeds]")
{
    // Sign with private key, verify with public-only key extracted from JSON
    JWK private_key = JWK::generateEC(JWK::Use::signature, "P-256");

    JWS jws;
    jws.setPayload("verify with public key");
    jws.setAlgorithm(JWA::SignatureAlgorithm::es256);
    string token = jws.sign(private_key);

    // Strip private key material
    JWK public_key = JWK::fromJSON(private_key.toJSON(false));
    bool result = JWS::verify(token, public_key);
    REQUIRE(result);
}
