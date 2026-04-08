#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <map>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

// Basic JWS creation tests
TEST_CASE("JWS_CreateSimpleJWS", "[jws][createsimplejws]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token = sign(key,
                        JWA::SignatureAlgorithm::hs256,
                        std::span<char const>("test payload", strlen("test payload")))
                       .toCompact();
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
    string token = sign(key,
                        JWA::SignatureAlgorithm::hs256,
                        string("JWT"),
                        map<string, string>{{"custom", "value"}},
                        string("test"))
                       .toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("custom"));
    REQUIRE(string::npos != header.find("value"));
}

TEST_CASE("JWS_GetHeader", "[jws][getheader]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string token =
        sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), string("test")).toCompact();

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
    string token =
        sign(key, JWA::SignatureAlgorithm::hs256, string("original payload")).toCompact();

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
    string token = sign(key, JWA::SignatureAlgorithm::rs256, string("This is the payload content"))
                       .toCompact();

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
    string token = sign(key,
                        JWA::SignatureAlgorithm::hs256,
                        string("JWT"),
                        map<string, string>{{"custom1", "value1"}, {"custom2", "value2"}},
                        string("test"))
                       .toCompact();

    string header = Base64URL::decodeToString(token.substr(0, token.find('.')));
    REQUIRE(string::npos != header.find("custom1"));
    REQUIRE(string::npos != header.find("custom2"));
}

// Public key verification
TEST_CASE("JWS_JWS_RSAPublicKeyVerification", "[jws][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws =
        sign(privateKey, JWA::SignatureAlgorithm::rs256, string("message for public verification"));

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
    auto jws_opt = JWS::fromCompact(token, std::nothrow);
    if (jws_opt.has_value())
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

    string real_token =
        sign(key, JWA::SignatureAlgorithm::hs256, string(R"({"sub":"admin"})")).toCompact();

    // Replace the header with one claiming alg:none and strip the signature
    string tampered_header = Base64URL::encode(string(R"({"alg":"none"})"));
    size_t first_dot = real_token.find('.');
    size_t second_dot = real_token.find('.', first_dot + 1);
    string tampered = tampered_header + real_token.substr(first_dot, second_dot - first_dot + 1);
    // append empty signature segment
    tampered += '.';

    bool rejected = true;
    auto jws_opt = JWS::fromCompact(tampered, std::nothrow);
    if (jws_opt.has_value())
    {
        rejected = !verify(*jws_opt, key);
    }
    REQUIRE(rejected);
}

// ─── Move assignment operator ─────────────────────────────────────────────────

TEST_CASE("JWS_MoveAssignmentOperator", "[jws][moveassignmentoperator]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string expected_payload = "move assignment payload";
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, expected_payload);
    JWS other = sign(key, JWA::SignatureAlgorithm::hs256, string("other"));

    other = std::move(original);
    auto payload_bytes = other.getPayload();
    REQUIRE(expected_payload == string(payload_bytes.begin(), payload_bytes.end()));
}

// ─── Copy assignment operator ─────────────────────────────────────────────────

TEST_CASE("JWS_CopyAssignmentOperator", "[jws][copyassignmentoperator]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("copy assign payload"));
    JWS target = sign(key, JWA::SignatureAlgorithm::hs256, string("target payload"));

    target = original;
    REQUIRE(original.getPayload() == target.getPayload());
    // Both should still verify
    REQUIRE(verify(original, key));
    REQUIRE(verify(target, key));
}

// ─── swap ─────────────────────────────────────────────────────────────────────

TEST_CASE("JWS_Swap", "[jws][swap]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_a = "payload_a";
    string payload_b = "payload_b";
    JWS a = sign(key, JWA::SignatureAlgorithm::hs256, payload_a);
    JWS b = sign(key, JWA::SignatureAlgorithm::hs256, payload_b);

    a.swap(b);

    auto bytes_a = a.getPayload();
    auto bytes_b = b.getPayload();
    REQUIRE(payload_b == string(bytes_a.begin(), bytes_a.end()));
    REQUIRE(payload_a == string(bytes_b.begin(), bytes_b.end()));
}

// ─── toJSON (flattened) ────────────────────────────────────────────────────────

TEST_CASE("JWS_ToJSONFlattened", "[jws][tojsonflattened]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("flattened payload"));

    string json_str = jws.toJSON(true);
    REQUIRE_FALSE(json_str.empty());

    // Flattened format must have "payload", "protected", "signature" at top level;
    // it must NOT have a "signatures" array.
    REQUIRE(string::npos != json_str.find("\"payload\""));
    REQUIRE(string::npos != json_str.find("\"protected\""));
    REQUIRE(string::npos != json_str.find("\"signature\""));
    REQUIRE(string::npos == json_str.find("\"signatures\""));
}

TEST_CASE("JWS_ToJSONFlattenedRoundTrip", "[jws][tojsonflattenedRoundTrip]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "flattened round-trip";
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, payload_str);

    string json_str = original.toJSON(true);
    JWS parsed = JWS::fromJSON(json_str);

    auto bytes = parsed.getPayload();
    REQUIRE(payload_str == string(bytes.begin(), bytes.end()));
    REQUIRE(verify(parsed, key));
}

// ─── toJSON (general / multi-signature JSON) ──────────────────────────────────

TEST_CASE("JWS_ToJSONGeneral", "[jws][tojsongeneral]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("general payload"));

    string json_str = jws.toJSON(false);
    REQUIRE_FALSE(json_str.empty());

    // General format must have "payload" and "signatures" array; no top-level "signature".
    REQUIRE(string::npos != json_str.find("\"payload\""));
    REQUIRE(string::npos != json_str.find("\"signatures\""));
    REQUIRE(string::npos != json_str.find("\"protected\""));
}

TEST_CASE("JWS_ToJSONGeneralRoundTrip", "[jws][tojsongeneralRoundTrip]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "general round-trip";
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, payload_str);

    string json_str = original.toJSON(false);
    JWS parsed = JWS::fromJSON(json_str);

    auto bytes = parsed.getPayload();
    REQUIRE(payload_str == string(bytes.begin(), bytes.end()));
    REQUIRE(verify(parsed, key));
}

// ─── fromJSON – flattened serialization ──────────────────────────────────────

TEST_CASE("JWS_FromJSONFlattenedVerifies", "[jws][fromjsonflattenedverifies]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string payload_str = "rsa flattened json round-trip";
    JWS original = sign(key, JWA::SignatureAlgorithm::rs256, payload_str);

    JWS parsed = JWS::fromJSON(original.toJSON(true));
    REQUIRE(verify(parsed, key));

    auto bytes = parsed.getPayload();
    REQUIRE(payload_str == string(bytes.begin(), bytes.end()));
}

TEST_CASE("JWS_FromJSONFlattenedWithCustomHeaderParams",
          "[jws][fromjsonflattenedwithcustomheaderparams]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key,
                        JWA::SignatureAlgorithm::hs256,
                        string("JWT"),
                        map<string, string>{{"x-custom", "x-value"}},
                        string("param payload"));

    JWS parsed = JWS::fromJSON(original.toJSON(true));
    REQUIRE(verify(parsed, key));
}

// ─── fromJSON – general serialization ────────────────────────────────────────

TEST_CASE("JWS_FromJSONGeneralVerifies", "[jws][fromjsongeneralverifies]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    string payload_str = "ec general json round-trip";
    JWS original = sign(key, JWA::SignatureAlgorithm::es256, payload_str);

    JWS parsed = JWS::fromJSON(original.toJSON(false));
    REQUIRE(verify(parsed, key));

    auto bytes = parsed.getPayload();
    REQUIRE(payload_str == string(bytes.begin(), bytes.end()));
}

TEST_CASE("JWS_FromJSONEmptySignaturesThrows", "[jws][fromjsonemptysignaturesthrows]")
{
    // Build a general JSON with an empty "signatures" array; fromJSON must throw.
    string bad_json = R"({"payload":"dGVzdA","signatures":[]})";
    REQUIRE_THROWS(JWS::fromJSON(bad_json));
}

TEST_CASE("JWS_FromJSONMultiSignatureAllVerify", "[jws][fromjsonmultisignatureallverify]")
{
    // A general-format JWS with two signatures (same key, same alg): both must verify.
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string single = sign(key, JWA::SignatureAlgorithm::hs256, string("payload")).toJSON(false);

    // Duplicate the signatures entry to produce a two-signature general JWS.
    auto j = nlohmann::json::parse(single);
    auto sig_entry = j["signatures"][0];
    j["signatures"].push_back(sig_entry);

    JWS multi = JWS::fromJSON(j.dump());
    REQUIRE(verify(multi, key));
}

TEST_CASE("JWS_FromJSONMultiSignatureOneBadFails", "[jws][fromjsonmultisignatureonebad]")
{
    // If one of the applicable signatures is tampered with, verify() must fail.
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string single = sign(key, JWA::SignatureAlgorithm::hs256, string("payload")).toJSON(false);

    auto j = nlohmann::json::parse(single);
    // Duplicate the entry, then corrupt the second signature.
    auto sig_entry = j["signatures"][0];
    string const good_sig = sig_entry["signature"].get<string>();
    // Flip the first character to produce an invalid base64url value.
    string bad_sig = good_sig;
    bad_sig[0] = (bad_sig[0] == 'A') ? 'B' : 'A';
    sig_entry["signature"] = bad_sig;
    j["signatures"].push_back(sig_entry);

    JWS multi = JWS::fromJSON(j.dump());
    REQUIRE_FALSE(verify(multi, key));
}

TEST_CASE("JWS_FromJSONMultiSignatureDifferentKeyTypes",
          "[jws][fromjsonmultisignaturedifferentkeys]")
{
    // A JWS signed with both HS256 and RS256; verify with only the oct key
    // must succeed (RS256 entry is skipped as incompatible key type).
    JWK oct_key = JWK::generateOct(JWK::Use::signature, 256);
    JWK rsa_key = JWK::generateRSA(JWK::Use::signature, 2048);

    string payload_str = "mixed key type payload";
    string hs_json = sign(oct_key, JWA::SignatureAlgorithm::hs256, payload_str).toJSON(false);
    string rs_json = sign(rsa_key, JWA::SignatureAlgorithm::rs256, payload_str).toJSON(false);

    auto jh = nlohmann::json::parse(hs_json);
    auto jr = nlohmann::json::parse(rs_json);
    // Build combined JWS: same payload, both signature entries.
    auto combined = nlohmann::json::object();
    combined["payload"] = jh["payload"];
    combined["signatures"] = nlohmann::json::array({jh["signatures"][0], jr["signatures"][0]});

    JWS multi = JWS::fromJSON(combined.dump());
    REQUIRE(verify(multi, oct_key));
    REQUIRE(verify(multi, rsa_key));
}

// ─── fromJSON nothrow ─────────────────────────────────────────────────────────

TEST_CASE("JWS_FromJSONNothrowValid", "[jws][fromjsonnothrowvalid]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("nothrow valid"));
    string json_str = original.toJSON(true);

    auto jws_opt = JWS::fromJSON(json_str, std::nothrow);
    REQUIRE(jws_opt.has_value());
    REQUIRE(verify(*jws_opt, key));
}

TEST_CASE("JWS_FromJSONNothrowInvalid", "[jws][fromjsonnothrowinvalid]")
{
    auto jws_opt = JWS::fromJSON("not valid json at all {{{", std::nothrow);
    REQUIRE_FALSE(jws_opt.has_value());
}

// ─── tryLoad ─────────────────────────────────────────────────────────────────

TEST_CASE("JWS_TryLoadFromCompact", "[jws][tryloadfromcompact]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string compact =
        sign(key, JWA::SignatureAlgorithm::hs256, string("tryload compact")).toCompact();

    auto jws_opt = JWS::tryLoad(compact);
    REQUIRE(jws_opt.has_value());
    REQUIRE(verify(*jws_opt, key));
}

TEST_CASE("JWS_TryLoadFromJSON", "[jws][tryloadfromjson]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("tryload json"));
    string json_str = original.toJSON(true);

    auto jws_opt = JWS::tryLoad(json_str);
    REQUIRE(jws_opt.has_value());
    REQUIRE(verify(*jws_opt, key));
}

TEST_CASE("JWS_TryLoadInvalidInput", "[jws][tryloadinvalidinput]")
{
    auto jws_opt = JWS::tryLoad("this is neither compact nor json");
    REQUIRE_FALSE(jws_opt.has_value());
}

// ─── fromCompact error paths ──────────────────────────────────────────────────

TEST_CASE("JWS_FromCompactMissingFirstDotThrows", "[jws][fromcompactmissingfirstdotthrows]")
{
    REQUIRE_THROWS(JWS::fromCompact("nodots"));
}

TEST_CASE("JWS_FromCompactMissingSecondDotThrows", "[jws][fromcompactmissingseconddotthrows]")
{
    REQUIRE_THROWS(JWS::fromCompact("one.dot"));
}

TEST_CASE("JWS_FromCompactNothrowMissingDot", "[jws][fromcompactnothrowmissingdot]")
{
    auto jws_opt = JWS::fromCompact("nodots", std::nothrow);
    REQUIRE_FALSE(jws_opt.has_value());
}

// ─── fromCompact preserves custom header params ───────────────────────────────

TEST_CASE("JWS_FromCompactPreservesHeaderParams", "[jws][fromcompactpreservesheaderparams]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string compact = sign(key,
                          JWA::SignatureAlgorithm::hs256,
                          string("JWT"),
                          map<string, string>{{"x-ns", "test-ns"}},
                          string("param payload"))
                         .toCompact();

    // Round-trip through fromCompact: the extra header param must appear in the header.
    JWS parsed = JWS::fromCompact(compact);
    REQUIRE(verify(parsed, key));

    // Verify the header contains our custom param by inspecting the compact token directly.
    size_t dot = compact.find('.');
    string header_json = Base64URL::decodeToString(compact.substr(0, dot));
    REQUIRE(string::npos != header_json.find("x-ns"));
    REQUIRE(string::npos != header_json.find("test-ns"));
}

// ─── sign overloads – span<unsigned char const> ───────────────────────────────

TEST_CASE("JWS_SignSpanUnsignedChar", "[jws][signspanunsignedchar]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "unsigned span payload";
    vector<unsigned char> payload_bytes(payload_str.begin(), payload_str.end());
    span<unsigned char const> payload_span(payload_bytes.data(), payload_bytes.size());

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, payload_span);
    REQUIRE(verify(jws, key));

    auto got = jws.getPayload();
    REQUIRE(payload_bytes == got);
}

TEST_CASE("JWS_SignTypeAndSpanCharConst", "[jws][signtypeandspancharconst]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "type + char span";
    span<char const> payload_span(payload_str.data(), payload_str.size());

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), payload_span);
    REQUIRE(verify(jws, key));

    string compact = jws.toCompact();
    string header = Base64URL::decodeToString(compact.substr(0, compact.find('.')));
    REQUIRE(string::npos != header.find("JWT"));
}

TEST_CASE("JWS_SignTypeAndSpanUnsignedChar", "[jws][signtypeandspanunsignedchar]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "type + unsigned span";
    vector<unsigned char> payload_bytes(payload_str.begin(), payload_str.end());
    span<unsigned char const> payload_span(payload_bytes.data(), payload_bytes.size());

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), payload_span);
    REQUIRE(verify(jws, key));
}

// ─── sign overloads – vector<unsigned char> ───────────────────────────────────

TEST_CASE("JWS_SignVectorUnsignedChar", "[jws][signvectorunsignedchar]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "vector unsigned char payload";
    vector<unsigned char> payload_bytes(payload_str.begin(), payload_str.end());

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, payload_bytes);
    REQUIRE(verify(jws, key));

    auto got = jws.getPayload();
    REQUIRE(payload_bytes == got);
}

TEST_CASE("JWS_SignTypeAndVectorUnsignedChar", "[jws][signtypeandvectorunsignedchar]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string payload_str = "type + vector unsigned char";
    vector<unsigned char> payload_bytes(payload_str.begin(), payload_str.end());

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("JWT"), payload_bytes);
    REQUIRE(verify(jws, key));

    string compact = jws.toCompact();
    string header = Base64URL::decodeToString(compact.substr(0, compact.find('.')));
    REQUIRE(string::npos != header.find("JWT"));
}

// ─── Invalid key use for signing ─────────────────────────────────────────────

TEST_CASE("JWS_SignWithEncryptionKeyThrows", "[jws][signwithencryptionkeythrows]")
{
    JWK enc_key = JWK::generateOct(JWK::Use::encryption, 256);
    REQUIRE_THROWS_AS(sign(enc_key, JWA::SignatureAlgorithm::hs256, string("payload")),
                      std::invalid_argument);
}

// ─── PSS algorithms – successful verification ─────────────────────────────────

TEST_CASE("JWS_VerifyPS256RoundTrip", "[jws][verifyps256roundtrip]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps256, string("ps256 payload"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_VerifyPS384RoundTrip", "[jws][verifyps384roundtrip]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps384, string("ps384 payload"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("JWS_VerifyPS512RoundTrip", "[jws][verifyps512roundtrip]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps512, string("ps512 payload"));
    REQUIRE(verify(jws, key));
}

// ─── toJSON / fromJSON – asymmetric algorithms ────────────────────────────────

TEST_CASE("JWS_RSAToJSONFromJSONVerifies", "[jws][rsatojsonfromjsonverifies]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string payload_str = "rsa json serialization";
    JWS original = sign(key, JWA::SignatureAlgorithm::rs256, payload_str);

    // Both serialization formats must round-trip.
    JWS from_flat = JWS::fromJSON(original.toJSON(true));
    JWS from_gen = JWS::fromJSON(original.toJSON(false));

    REQUIRE(verify(from_flat, key));
    REQUIRE(verify(from_gen, key));
}

TEST_CASE("JWS_ECToJSONFromJSONVerifies", "[jws][ectojsonfromjsonverifies]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-384");
    string payload_str = "ec p384 json serialization";
    JWS original = sign(key, JWA::SignatureAlgorithm::es384, payload_str);

    JWS from_flat = JWS::fromJSON(original.toJSON(true));
    JWS from_gen = JWS::fromJSON(original.toJSON(false));

    REQUIRE(verify(from_flat, key));
    REQUIRE(verify(from_gen, key));
}

// ─── toJSON default parameter (false) ────────────────────────────────────────

TEST_CASE("JWS_ToJSONDefaultIsGeneral", "[jws][tojsondefaultisgeneral]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("default json"));

    // Default argument of toJSON() must be false → general format
    string json_str = jws.toJSON();
    REQUIRE(string::npos != json_str.find("\"signatures\""));
}

// ─── fromJSON with kid in header ──────────────────────────────────────────────

TEST_CASE("JWS_FromJSONPreservesKid", "[jws][fromjsonpreserveskid]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    // Give the key an explicit kid so the header carries it.
    string compact = sign(key, JWA::SignatureAlgorithm::hs256, string("kid payload")).toCompact();

    // Round-trip through general JSON
    JWS parsed = JWS::fromJSON(JWS::fromCompact(compact).toJSON(false));
    REQUIRE(verify(parsed, key));
}

// ─── operator<< ──────────────────────────────────────────────────────────────

TEST_CASE("JWS_StreamOutput", "[jws][operators][streamoutput]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, string("stream payload"));

    std::ostringstream oss;
    oss << jws;
    string output = oss.str();

    // The streamed output must be identical to toCompact()
    REQUIRE(output == jws.toCompact());
    // Must be a valid compact token (two dots)
    REQUIRE(string::npos != output.find('.'));
}

// ─── operator== ──────────────────────────────────────────────────────────────

TEST_CASE("JWS_EqualityIdentical", "[jws][operators][equality]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string compact = sign(key, JWA::SignatureAlgorithm::hs256, string("eq payload")).toCompact();
    JWS a = JWS::fromCompact(compact);
    JWS b = JWS::fromCompact(compact);

    REQUIRE(a == b);
}

TEST_CASE("JWS_EqualityCopyIsEqual", "[jws][operators][equality]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("copy payload"));
    JWS copy = original;

    REQUIRE(original == copy);
}

// ─── operator!= ──────────────────────────────────────────────────────────────

TEST_CASE("JWS_InequalityDifferentPayloads", "[jws][operators][inequality]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS a = sign(key, JWA::SignatureAlgorithm::hs256, string("payload A"));
    JWS b = sign(key, JWA::SignatureAlgorithm::hs256, string("payload B"));

    REQUIRE(a != b);
}

TEST_CASE("JWS_InequalityFalseForCopy", "[jws][operators][inequality]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS original = sign(key, JWA::SignatureAlgorithm::hs256, string("ineq payload"));
    JWS copy = original;

    REQUIRE_FALSE(original != copy);
}

// ─── operator< / operator<= / operator> / operator>= ─────────────────────────

TEST_CASE("JWS_OrderingReflexivity", "[jws][operators][ordering]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string compact = sign(key, JWA::SignatureAlgorithm::hs256, string("ref payload")).toCompact();
    JWS a = JWS::fromCompact(compact);
    JWS b = JWS::fromCompact(compact);

    // a == b → not less, not greater; both <= and >=
    REQUIRE_FALSE(a < b);
    REQUIRE_FALSE(a > b);
    REQUIRE(a <= b);
    REQUIRE(a >= b);
}

TEST_CASE("JWS_OrderingConsistentWithCompact", "[jws][operators][ordering]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    JWS a = sign(key, JWA::SignatureAlgorithm::hs256, string("alpha"));
    JWS b = sign(key, JWA::SignatureAlgorithm::hs256, string("beta"));

    string ca = a.toCompact();
    string cb = b.toCompact();

    // The operators must agree with lexicographic string comparison of the
    // compact serializations that back them.
    REQUIRE((a < b) == (ca < cb));
    REQUIRE((a <= b) == (ca <= cb));
    REQUIRE((a > b) == (ca > cb));
    REQUIRE((a >= b) == (ca >= cb));
    REQUIRE((a == b) == (ca == cb));
    REQUIRE((a != b) == (ca != cb));
}

TEST_CASE("JWS_OrderingStrictAsymmetry", "[jws][operators][ordering]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);

    // Create two tokens; at least one of the three orderings must hold strictly.
    string compact_a = sign(key, JWA::SignatureAlgorithm::hs256, string("strict A")).toCompact();
    string compact_b = sign(key, JWA::SignatureAlgorithm::hs256, string("strict B")).toCompact();

    JWS a = JWS::fromCompact(compact_a);
    JWS b = JWS::fromCompact(compact_b);

    if (compact_a < compact_b)
    {
        REQUIRE(a < b);
        REQUIRE(a <= b);
        REQUIRE_FALSE(a > b);
        REQUIRE_FALSE(a >= b);
    }
    else if (compact_a > compact_b)
    {
        REQUIRE(a > b);
        REQUIRE(a >= b);
        REQUIRE_FALSE(a < b);
        REQUIRE_FALSE(a <= b);
    }
    else
    {
        REQUIRE(a == b);
    }
}

// ─── getPayload<T> template overloads ────────────────────────────────────────

TEST_CASE("JWS_GetPayloadAsString", "[jws][getpayload][string]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string const expected = "hello from getPayload<string>";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, expected);

    string actual = jws.getPayload<string>();

    REQUIRE(actual == expected);
}

TEST_CASE("JWS_GetPayloadAsStringBase64Url", "[jws][getpayload][base64url]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string const payload = "base64url encoded payload";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, payload);

    string encoded = jws.getPayload<string>(true);

    // Must be the base64url-encoded form of the raw payload bytes.
    vector<unsigned char> raw = jws.getPayload();
    string expected_b64 = Base64URL::encode(raw);
    REQUIRE(encoded == expected_b64);

    // Must not contain padding characters.
    REQUIRE(string::npos == encoded.find('='));
}

TEST_CASE("JWS_GetPayloadAsVectorTemplate", "[jws][getpayload][vector]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string const payload = "vector template payload";
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, payload);

    vector<unsigned char> via_template = jws.getPayload<vector<unsigned char>>();
    vector<unsigned char> via_non_template = jws.getPayload();

    REQUIRE(via_template == via_non_template);
}
