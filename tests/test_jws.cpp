#include <catch2/catch_test_macros.hpp>
#include <map>
#include <string>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

// Basic JWS creation tests
TEST_CASE("JWS_CreateSimpleJWS", "[jws][createsimplejws]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, std::span<char const>("test payload", strlen("test payload"))).toCompact();
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
        string token = sign(key, alg, std::span<char const>("test", strlen("test"))).toCompact();
        REQUIRE_FALSE(token.empty());
    }
}

TEST_CASE("JWS_SetCustomHeaderParam", "[jws][setcustomheaderparam]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), map<string, string>{{"custom", "value"}}, string("test")).toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("custom"));
    REQUIRE(string::npos != header.find("value"));
}

TEST_CASE("JWS_GetHeader", "[jws][getheader]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), string("test")).toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE_FALSE(header.empty());
    REQUIRE(string::npos != header.find("alg"));
    REQUIRE(string::npos != header.find("HS256"));
}

TEST_CASE("JWS_GetAlgorithm", "[jws][getalgorithm]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string token = sign(key, JWA::SignatureAlgorithm::rs256, string("test")).toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("RS256"));
}

// Verification tests
TEST_CASE("JWS_VerifyValidHS256", "[jws][verifyvalidhs256]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("secure message"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_VerifyValidRS256", "[jws][verifyvalidrs256]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::rs256, string("rsa signed message"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_VerifyValidES256", "[jws][verifyvalides256]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    JWS jws = sign(key, JWA::SignatureAlgorithm::es256, string("ecdsa signed message"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_VerifyWithWrongKeyFails", "[jws][verifywithwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(JWK::Use::signature, 256);
    JWK key2 = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key1, JWA::SignatureAlgorithm::hs256, string("message"));
    REQUIRE_FALSE(verify(jws, key2));
}

TEST_CASE("JWS_VerifyTamperedPayloadFails", "[jws][verifytamperedpayloadfails]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, string("original payload")).toCompact();

    // Tamper with token by modifying the payload part
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot != string::npos && secondDot != string::npos)
    {
        token[firstDot + 1] = (token[firstDot + 1] == 'A') ? 'B' : 'A';
    }

    REQUIRE_FALSE(verify(JWS::fromCompact(token), key));
}

TEST_CASE("JWS_VerifyTamperedSignatureFails", "[jws][verifytamperedsignaturefails]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, string("payload")).toCompact();

    // Tamper with signature
    size_t lastDot = token.rfind('.');
    if (lastDot != string::npos && lastDot + 1 < token.length())
    {
        token[lastDot + 1] = (token[lastDot + 1] == 'A') ? 'B' : 'A';
    }

    REQUIRE_FALSE(verify(JWS::fromCompact(token), key));
}

// Parsing tests
TEST_CASE("JWS_ParseJWS", "[jws][parsejws]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::hs256, string("test payload")).toCompact();

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE("test payload" == string(payload_bytes.begin(), payload_bytes.end()));
    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("HS256"));
}

TEST_CASE("JWS_ParseAndGetPayload", "[jws][parseandgetpayload]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string token = sign(key, JWA::SignatureAlgorithm::rs256, string("This is the payload content")).toCompact();

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE("This is the payload content" == string(payload_bytes.begin(), payload_bytes.end()));
}

// Copy and move semantics
TEST_CASE("JWS_CopyConstructor", "[jws][copyconstructor]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("test"));

    JWS copy(original);
    REQUIRE(original.getPayload() == copy.getPayload());
}

TEST_CASE("JWS_CopyAssignment", "[jws][copyassignment]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("test"));

    JWS copy = original;
    REQUIRE(original.getPayload() == copy.getPayload());
}

TEST_CASE("JWS_MoveConstructor", "[jws][moveconstructor]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string expected_payload = "test payload";
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, expected_payload);

    JWS moved(std::move(original));
    auto payload_bytes = moved.getPayload();
    REQUIRE(expected_payload == string(payload_bytes.begin(), payload_bytes.end()));
}

TEST_CASE("JWS_MoveAssignment", "[jws][moveassignment]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string expected_payload = "test payload";
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, expected_payload);

    JWS moved = std::move(original);
    auto payload_bytes = moved.getPayload();
    REQUIRE(expected_payload == string(payload_bytes.begin(), payload_bytes.end()));
}

// Edge cases
TEST_CASE("JWS_EmptyPayload", "[jws][emptypayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string(""));
    string token = jws.toCompact();
    REQUIRE_FALSE(token.empty());
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_LargePayload", "[jws][largepayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string largePayload(10000, 'X');
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, largePayload);
    string token = jws.toCompact();
    REQUIRE_FALSE(token.empty());

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE(largePayload == string(payload_bytes.begin(), payload_bytes.end()));
}

TEST_CASE("JWS_PayloadWithSpecialCharacters", "[jws][payloadwithspecialcharacters]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "Special chars: \n\t\r\"'{}[]";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, payload_str);
    string token = jws.toCompact();

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE(payload_str == string(payload_bytes.begin(), payload_bytes.end()));
}

TEST_CASE("JWS_JSONPayload", "[jws][jsonpayload]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string jsonPayload = R"({"name":"John","age":30,"city":"New York"})";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, jsonPayload);
    string token = jws.toCompact();

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE(jsonPayload == string(payload_bytes.begin(), payload_bytes.end()));
}

TEST_CASE("JWS_MultipleHeaderParams", "[jws][multipleheaderparams]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(
        key,
        JWA::SignatureAlgorithm::hs256,
        string("JWT"),
        map<string, string>{{"custom1", "value1"}, {"custom2", "value2"}},
        string("test")).toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("custom1"));
    REQUIRE(string::npos != header.find("custom2"));
}

// Public key verification
TEST_CASE("JWS_JWS_RSAPublicKeyVerification", "[jws][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(privateKey, JWA::SignatureAlgorithm::rs256, string("message for public verification"));

    // Extract public key
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    REQUIRE(verify(jws, publicKey));
}

TEST_CASE("JWS_ECPublicKeyVerification", "[jws][ecpublickeyverification]")
{
    JWK privateKey = JWK::generateEC(JWK::Use::signature, "P-256");
    JWS jws = sign(privateKey, JWA::SignatureAlgorithm::es256, string("ec message"));

    // Extract public key
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    REQUIRE(verify(jws, publicKey));
}

// Interoperability test
TEST_CASE("JWS_CreateWithJWSVerifyWithJWT", "[jws][createwithjwsverifywithjwt]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = R"({"sub":"1234567890","name":"John Doe","iat":1516239022})";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), payload_str);

    REQUIRE(verify(jws, key));
}

// ─── Wrong-key failure tests for asymmetric algorithms ───────────────────────

TEST_CASE("JWS_VerifyWithWrongECKeyFails", "[jws][verifywithwrongeckeyfails]")
{
    JWK key1 = JWK::generateEC(JWK::Use::signature, "P-256");
    JWK key2 = JWK::generateEC(JWK::Use::signature, "P-256");
    JWS jws = sign(key1, JWA::SignatureAlgorithm::es256, string("signed with key1"));
    REQUIRE_FALSE(verify(jws, key2));
}

TEST_CASE("JWS_VerifyWithWrongRSAKeyFails", "[jws][verifywithwrongrsakkeyfails]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key1, JWA::SignatureAlgorithm::rs256, string("signed with rsa key1"));
    REQUIRE_FALSE(verify(jws, key2));
}

TEST_CASE("JWS_VerifyWithWrongPSSKeyFails", "[jws][verifywithwrongpsskeyfails]")
{
    JWK key1 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK key2 = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key1, JWA::SignatureAlgorithm::ps256, string("signed with pss key1"));
    REQUIRE_FALSE(verify(jws, key2));
}

TEST_CASE("JWS_VerifyES256PublicKeyOnlySucceeds", "[jws][verifyes256publickeyonlysucceeds]")
{
    // Sign with private key, verify with public-only key extracted from JSON
    JWK private_key = JWK::generateEC(JWK::Use::signature, "P-256");
    JWS jws = sign(private_key, JWA::SignatureAlgorithm::es256, string("verify with public key"));

    // Strip private key material
    JWK public_key = JWK::fromJSON(private_key.toJSON(false));
    REQUIRE(verify(jws, public_key));
}

// ─── "none" algorithm tests ───────────────────────────────────────────────────

TEST_CASE("JWS_NoneAlgorithmRoundTrip", "[jws][nonealgorithmroundtrip]")
{
    // alg:none produces header.payload. (empty third segment); payload survives parse
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key, JWA::SignatureAlgorithm::none, string("unsigned payload")).toCompact();

    // Token must end with '.' (empty signature segment)
    REQUIRE(token.back() == '.');

    JWS parsed = JWS::fromCompact(token);
    auto payload_bytes = parsed.getPayload();
    REQUIRE("unsigned payload" == string(payload_bytes.begin(), payload_bytes.end()));
    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("none"));
}

TEST_CASE("JWS_NoneAlgorithmNonEmptySignatureRejected",
          "[jws][nonealgorithmnonemptysignaturerejected]")
{
    // A token claiming alg:none but carrying a non-empty signature must be rejected
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    // Build a well-formed none token, then append garbage to the signature segment
    string token = sign(key, JWA::SignatureAlgorithm::none, string("payload")).toCompact();
    token += "AAAA";  // non-empty signature

    bool rejected = true;
    auto [jws_opt, ok] = JWS::fromCompact(token, std::nothrow);
    if (ok && jws_opt.has_value())
    {
        rejected = !verify(*jws_opt, key);
    }
    REQUIRE(rejected);
}

TEST_CASE("JWS_NoneDowngradeAttackRejected", "[jws][nonedowngradeattackrejected]")
{
    // An attacker strips the signature from a legitimately signed token and
    // rewrites alg to "none".  verify() must reject it even though the key
    // parameter is present, because accepting a "none"-algorithm token when
    // the caller supplies a key is a well-known algorithm-confusion attack.
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    string real_token = sign(key, JWA::SignatureAlgorithm::hs256, string(R"({"sub":"admin"})")).toCompact();

    // Replace the header with one claiming alg:none and strip the signature
    string tampered_header = Base64URL::encode(string(R"({"alg":"none"})"));
    size_t first_dot = real_token.find('.');
    size_t second_dot = real_token.find('.', first_dot + 1);
    string tampered = tampered_header + real_token.substr(first_dot, second_dot - first_dot + 1);
    // append empty signature segment
    tampered += '.';

    bool rejected = true;
    auto [jws_opt, ok] = JWS::fromCompact(tampered, std::nothrow);
    if (ok && jws_opt.has_value())
    {
        rejected = !verify(*jws_opt, key);
    }
    REQUIRE(rejected);
}
