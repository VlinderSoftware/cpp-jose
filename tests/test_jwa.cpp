#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace std;

using namespace Vlinder::JOSE;

namespace {
void verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm algorithm,
                                                           JWK const &original_private_key,
                                                           vector<unsigned char> const &data)
{
    JWK original_public_key = JWK::fromJSON(original_private_key.toJSON(false));

    string private_key_json = original_private_key.toJSON(true);
    string public_key_json = original_private_key.toJSON(false);

    JWK deserialized_private_key = JWK::fromJSON(private_key_json);
    JWK deserialized_public_key = JWK::fromJSON(public_key_json);

    string payload_str(data.begin(), data.end());

    JWS jws_from_original = sign(original_private_key, algorithm, payload_str);
    REQUIRE(verify(jws_from_original, original_public_key));
    REQUIRE(verify(jws_from_original, deserialized_public_key));

    JWS jws_from_deserialized = sign(deserialized_private_key, algorithm, payload_str);
    REQUIRE(verify(jws_from_deserialized, original_public_key));
    REQUIRE(verify(jws_from_deserialized, deserialized_public_key));
}

void verifyRsaKeyEncryptionSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm algorithm,
                                                              vector<unsigned char> const &cek)
{
    JWK original_private_key = JWK::generateRSA(JWK::Use::encryption, 2048);
    JWK original_public_key = JWK::fromJSON(original_private_key.toJSON(false));

    JWK deserialized_private_key = JWK::fromJSON(original_private_key.toJSON(true));
    JWK deserialized_public_key = JWK::fromJSON(original_private_key.toJSON(false));

    vector<unsigned char> encrypted = JWA::encryptKey(algorithm, original_public_key, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);
    REQUIRE(cek == JWA::decryptKey(algorithm, original_private_key, encrypted));

    encrypted = JWA::encryptKey(algorithm, original_public_key, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);
    REQUIRE(cek == JWA::decryptKey(algorithm, deserialized_private_key, encrypted));

    encrypted = JWA::encryptKey(algorithm, deserialized_public_key, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);
    REQUIRE(cek == JWA::decryptKey(algorithm, original_private_key, encrypted));

    encrypted = JWA::encryptKey(algorithm, deserialized_public_key, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);
    REQUIRE(cek == JWA::decryptKey(algorithm, deserialized_private_key, encrypted));
}

void verifySymmetricKeyWrapSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm algorithm,
                                                              unsigned int key_size_bits,
                                                              vector<unsigned char> const &cek)
{
    JWK original_kek = JWK::generateOct(JWK::Use::encryption, key_size_bits);
    JWK deserialized_kek = JWK::fromJSON(original_kek.toJSON(true));

    vector<unsigned char> encrypted = JWA::encryptKey(algorithm, original_kek, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek == JWA::decryptKey(algorithm, original_kek, encrypted));

    encrypted = JWA::encryptKey(algorithm, original_kek, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek == JWA::decryptKey(algorithm, deserialized_kek, encrypted));

    encrypted = JWA::encryptKey(algorithm, deserialized_kek, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek == JWA::decryptKey(algorithm, original_kek, encrypted));

    encrypted = JWA::encryptKey(algorithm, deserialized_kek, cek);
    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek == JWA::decryptKey(algorithm, deserialized_kek, encrypted));
}
}  // namespace

// Algorithm string conversion tests
TEST_CASE("SignatureAlgorithmToString", "[jwa][signaturealgorithmtostring]")
{
    REQUIRE("HS256" == JWA::toString(JWA::SignatureAlgorithm::hs256));
    REQUIRE("HS384" == JWA::toString(JWA::SignatureAlgorithm::hs384));
    REQUIRE("HS512" == JWA::toString(JWA::SignatureAlgorithm::hs512));
    REQUIRE("RS256" == JWA::toString(JWA::SignatureAlgorithm::rs256));
    REQUIRE("RS384" == JWA::toString(JWA::SignatureAlgorithm::rs384));
    REQUIRE("RS512" == JWA::toString(JWA::SignatureAlgorithm::rs512));
    REQUIRE("ES256" == JWA::toString(JWA::SignatureAlgorithm::es256));
    REQUIRE("ES384" == JWA::toString(JWA::SignatureAlgorithm::es384));
    REQUIRE("ES512" == JWA::toString(JWA::SignatureAlgorithm::es512));
    REQUIRE("PS256" == JWA::toString(JWA::SignatureAlgorithm::ps256));
    REQUIRE("PS384" == JWA::toString(JWA::SignatureAlgorithm::ps384));
    REQUIRE("PS512" == JWA::toString(JWA::SignatureAlgorithm::ps512));
    REQUIRE("none" == JWA::toString(JWA::SignatureAlgorithm::none));
}

TEST_CASE("KeyEncryptionAlgorithmToString", "[jwa][keyencryptionalgorithmtostring]")
{
    REQUIRE("RSA1_5" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa1_5));
    REQUIRE("RSA-OAEP" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa_oaep));
    REQUIRE("RSA-OAEP-256" == JWA::toString(JWA::KeyEncryptionAlgorithm::rsa_oaep_256));
    REQUIRE("A128KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a128kw));
    REQUIRE("A192KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a192kw));
    REQUIRE("A256KW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a256kw));
    REQUIRE("dir" == JWA::toString(JWA::KeyEncryptionAlgorithm::dir));
    REQUIRE("ECDH-ES" == JWA::toString(JWA::KeyEncryptionAlgorithm::ecdh_es));
    REQUIRE("A128GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a128gcmkw));
    REQUIRE("A192GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a192gcmkw));
    REQUIRE("A256GCMKW" == JWA::toString(JWA::KeyEncryptionAlgorithm::a256gcmkw));
}

TEST_CASE("ContentEncryptionAlgorithmToString", "[jwa][contentencryptionalgorithmtostring]")
{
    REQUIRE("A128CBC-HS256" == JWA::toString(JWA::ContentEncryptionAlgorithm::a128cbc_hs256));
    REQUIRE("A192CBC-HS384" == JWA::toString(JWA::ContentEncryptionAlgorithm::a192cbc_hs384));
    REQUIRE("A256CBC-HS512" == JWA::toString(JWA::ContentEncryptionAlgorithm::a256cbc_hs512));
    REQUIRE("A128GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a128gcm));
    REQUIRE("A192GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a192gcm));
    REQUIRE("A256GCM" == JWA::toString(JWA::ContentEncryptionAlgorithm::a256gcm));
}

TEST_CASE("SignatureAlgorithmFromString", "[jwa][signaturealgorithmfromstring]")
{
    REQUIRE(JWA::SignatureAlgorithm::hs256 == JWA::signatureAlgorithmFromString("HS256"));
    REQUIRE(JWA::SignatureAlgorithm::hs384 == JWA::signatureAlgorithmFromString("HS384"));
    REQUIRE(JWA::SignatureAlgorithm::hs512 == JWA::signatureAlgorithmFromString("HS512"));
    REQUIRE(JWA::SignatureAlgorithm::rs256 == JWA::signatureAlgorithmFromString("RS256"));
    REQUIRE(JWA::SignatureAlgorithm::rs384 == JWA::signatureAlgorithmFromString("RS384"));
    REQUIRE(JWA::SignatureAlgorithm::rs512 == JWA::signatureAlgorithmFromString("RS512"));
    REQUIRE(JWA::SignatureAlgorithm::es256 == JWA::signatureAlgorithmFromString("ES256"));
    REQUIRE(JWA::SignatureAlgorithm::es384 == JWA::signatureAlgorithmFromString("ES384"));
    REQUIRE(JWA::SignatureAlgorithm::es512 == JWA::signatureAlgorithmFromString("ES512"));
    REQUIRE(JWA::SignatureAlgorithm::ps256 == JWA::signatureAlgorithmFromString("PS256"));
    REQUIRE(JWA::SignatureAlgorithm::ps384 == JWA::signatureAlgorithmFromString("PS384"));
    REQUIRE(JWA::SignatureAlgorithm::ps512 == JWA::signatureAlgorithmFromString("PS512"));
    REQUIRE(JWA::SignatureAlgorithm::none == JWA::signatureAlgorithmFromString("none"));
}

// HMAC signature tests (HS256, HS384, HS512)
TEST_CASE("HS256SignAndVerify", "[jwa][hs256signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 256);
    string data_string = "test message";

    JWS jws = sign(key, JWA::SignatureAlgorithm::hs256, data_string);
    REQUIRE(verify(jws, key));
}

TEST_CASE("HS384SignAndVerify", "[jwa][hs384signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 384);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs384, string("test message for HS384"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("HS512SignAndVerify", "[jwa][hs512signandverify]")
{
    JWK key = JWK::generateOct(JWK::Use::signature, 512);
    JWS jws = sign(key, JWA::SignatureAlgorithm::hs512, string("test message for HS512"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("HMACWrongKeyFails", "[jwa][hmacwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(JWK::Use::signature, 256);
    JWK key2 = JWK::generateOct(JWK::Use::signature, 256);
    JWS jws = sign(key1, JWA::SignatureAlgorithm::hs256, string("test message"));
    REQUIRE_FALSE(verify(jws, key2));
}

// RSA signature tests (RS256, RS384, RS512)
TEST_CASE("RS256SignAndVerify", "[jwa][rs256signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::rs256, string("test message for RSA"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("RS384SignAndVerify", "[jwa][rs384signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::rs384, string("test message for RS384"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("RS512SignAndVerify", "[jwa][rs512signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::rs512, string("test message for RS512"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("RSAPublicKeyVerification", "[jwa][rsapublickeyverification]")
{
    JWK privateKey = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(privateKey, JWA::SignatureAlgorithm::rs256, string("test message"));

    // Export public key only
    string publicKeyJson = privateKey.toJSON(false);
    JWK publicKey = JWK::fromJSON(publicKeyJson);

    REQUIRE(verify(jws, publicKey));
}

TEST_CASE("RSASerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][rs256signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWK public_key = JWK::fromJSON(private_key.toJSON(false));

    JWK deserialized_private_key = JWK::fromJSON(private_key.toJSON(true));
    JWK deserialized_public_key = JWK::fromJSON(private_key.toJSON(false));

    string data_string = "test message for serialized/deserialized RSA key combinations";

    SECTION("Original private key signs, original public key verifies")
    {
        JWS jws = sign(private_key, JWA::SignatureAlgorithm::rs256, data_string);
        REQUIRE(verify(jws, public_key));
    }

    SECTION("Serialized/deserialized private key signs, original public key verifies")
    {
        JWS jws = sign(deserialized_private_key, JWA::SignatureAlgorithm::rs256, data_string);
        REQUIRE(verify(jws, public_key));
    }

    SECTION("Original private key signs, serialized/deserialized public key verifies")
    {
        JWS jws = sign(private_key, JWA::SignatureAlgorithm::rs256, data_string);
        REQUIRE(verify(jws, deserialized_public_key));
    }

    SECTION(
        "Serialized/deserialized private key signs, serialized/deserialized public key verifies")
    {
        JWS jws = sign(deserialized_private_key, JWA::SignatureAlgorithm::rs256, data_string);
        REQUIRE(verify(jws, deserialized_public_key));
    }
}

TEST_CASE("RS384SerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][rs384signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    string data_string = "test message for RS384 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::rs384,
                                                          private_key,
                                                          data);
}

TEST_CASE("RS512SerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][rs512signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    string data_string = "test message for RS512 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::rs512,
                                                          private_key,
                                                          data);
}

TEST_CASE("PS256SerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][ps256signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    string data_string = "test message for PS256 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::ps256,
                                                          private_key,
                                                          data);
}

TEST_CASE("PS384SerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][ps384signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    string data_string = "test message for PS384 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::ps384,
                                                          private_key,
                                                          data);
}

TEST_CASE("PS512SerializedDeserializedKeyCombinations",
          "[jwa][rsakeyserialization][ps512signandverify]")
{
    JWK private_key = JWK::generateRSA(JWK::Use::signature, 2048);
    string data_string = "test message for PS512 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::ps512,
                                                          private_key,
                                                          data);
}

TEST_CASE("ES256SerializedDeserializedKeyCombinations",
          "[jwa][eckeyserialization][es256signandverify]")
{
    JWK private_key = JWK::generateEC(JWK::Use::signature, "P-256");
    string data_string = "test message for ES256 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::es256,
                                                          private_key,
                                                          data);
}

TEST_CASE("ES384SerializedDeserializedKeyCombinations",
          "[jwa][eckeyserialization][es384signandverify]")
{
    JWK private_key = JWK::generateEC(JWK::Use::signature, "P-384");
    string data_string = "test message for ES384 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::es384,
                                                          private_key,
                                                          data);
}

TEST_CASE("ES512SerializedDeserializedKeyCombinations",
          "[jwa][eckeyserialization][es512signandverify]")
{
    JWK private_key = JWK::generateEC(JWK::Use::signature, "P-521");
    string data_string = "test message for ES512 serialized/deserialized key combinations";
    vector<unsigned char> data(data_string.begin(), data_string.end());

    verifyAsymmetricSerializedDeserializedKeyCombinations(JWA::SignatureAlgorithm::es512,
                                                          private_key,
                                                          data);
}

// ECDSA signature tests (ES256, ES384, ES512)
TEST_CASE("ES256SignAndVerify", "[jwa][es256signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-256");
    JWS jws = sign(key, JWA::SignatureAlgorithm::es256, string("test message for ECDSA"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("ES384SignAndVerify", "[jwa][es384signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-384");
    JWS jws = sign(key, JWA::SignatureAlgorithm::es384, string("test message for ES384"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("ES512SignAndVerify", "[jwa][es512signandverify]")
{
    JWK key = JWK::generateEC(JWK::Use::signature, "P-521");
    JWS jws = sign(key, JWA::SignatureAlgorithm::es512, string("test message for ES512"));
    REQUIRE(verify(jws, key));
}

// RSA-PSS signature tests (PS256, PS384, PS512)
TEST_CASE("PS256SignAndVerify", "[jwa][ps256signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps256, string("test message for PSS"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("PS384SignAndVerify", "[jwa][ps384signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps384, string("test message for PS384"));
    REQUIRE(verify(jws, key));
}

TEST_CASE("PS512SignAndVerify", "[jwa][ps512signandverify]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    JWS jws = sign(key, JWA::SignatureAlgorithm::ps512, string("test message for PS512"));
    REQUIRE(verify(jws, key));
}

// Signature tampering detection
TEST_CASE("TamperedSignatureFails", "[jwa][tamperedsignaturefails]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string token =
        sign(key, JWA::SignatureAlgorithm::rs256, string("original message")).toCompact();

    // Tamper with signature
    size_t lastDot = token.rfind('.');
    if (lastDot != string::npos && lastDot + 1 < token.length())
    {
        token[lastDot + 1] = (token[lastDot + 1] == 'A') ? 'B' : 'A';
    }

    REQUIRE_FALSE(verify(JWS::fromCompact(token), key));
}

TEST_CASE("TamperedDataFails", "[jwa][tampereddatafails]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string token =
        sign(key, JWA::SignatureAlgorithm::rs256, string("original message")).toCompact();

    // Tamper with payload (middle segment)
    size_t firstDot = token.find('.');
    size_t secondDot = token.find('.', firstDot + 1);
    if (firstDot != string::npos && secondDot != string::npos && firstDot + 1 < secondDot)
    {
        token[firstDot + 1] = (token[firstDot + 1] == 'A') ? 'B' : 'A';
    }

    REQUIRE_FALSE(verify(JWS::fromCompact(token), key));
}

// Key encryption tests
TEST_CASE("RSA_OAEP_EncryptDecrypt", "[jwa][rsa-oaep-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
    vector<unsigned char> cek(32, 0x42);  // 256-bit CEK

    vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep, key, cek);

    REQUIRE_FALSE(encrypted.empty());
    REQUIRE(cek != encrypted);

    vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("RSA_OAEP_256_EncryptDecrypt", "[jwa][rsa-oaep-256-encryptdecrypt]")
{
    JWK key = JWK::generateRSA(JWK::Use::encryption, 2048);
    vector<unsigned char> cek(32, 0x33);

    vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep_256, key, cek);

    REQUIRE_FALSE(encrypted.empty());

    vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::rsa_oaep_256, key, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A128KW_EncryptDecrypt", "[jwa][a128kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(JWK::Use::encryption, 128);
    vector<unsigned char> cek(16, 0x55);

    vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::a128kw, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::a128kw, kek, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("A256KW_EncryptDecrypt", "[jwa][a256kw-encryptdecrypt]")
{
    JWK kek = JWK::generateOct(JWK::Use::encryption, 256);
    vector<unsigned char> cek(32, 0x66);

    vector<unsigned char> encrypted =
        JWA::encryptKey(JWA::KeyEncryptionAlgorithm::a256kw, kek, cek);

    REQUIRE_FALSE(encrypted.empty());

    vector<unsigned char> decrypted =
        JWA::decryptKey(JWA::KeyEncryptionAlgorithm::a256kw, kek, encrypted);

    REQUIRE(cek == decrypted);
}

TEST_CASE("RSA_OAEP_SerializedDeserializedKeyCombinations",
          "[jwa][rsa-key-serialization][rsa-oaep-encryptdecrypt]")
{
    vector<unsigned char> cek(32, 0x2A);
    verifyRsaKeyEncryptionSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm::rsa_oaep,
                                                             cek);
}

TEST_CASE("RSA_OAEP_256_SerializedDeserializedKeyCombinations",
          "[jwa][rsa-key-serialization][rsa-oaep-256-encryptdecrypt]")
{
    vector<unsigned char> cek(32, 0x3C);
    verifyRsaKeyEncryptionSerializedDeserializedCombinations(
        JWA::KeyEncryptionAlgorithm::rsa_oaep_256,
        cek);
}

TEST_CASE("A128KW_SerializedDeserializedKeyCombinations",
          "[jwa][symmetric-key-serialization][a128kw-encryptdecrypt]")
{
    vector<unsigned char> cek(16, 0x6A);
    verifySymmetricKeyWrapSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm::a128kw,
                                                             128,
                                                             cek);
}

TEST_CASE("A192KW_SerializedDeserializedKeyCombinations",
          "[jwa][symmetric-key-serialization][a192kw-encryptdecrypt]")
{
    vector<unsigned char> cek(24, 0x6E);
    verifySymmetricKeyWrapSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm::a192kw,
                                                             192,
                                                             cek);
}

TEST_CASE("A256KW_SerializedDeserializedKeyCombinations",
          "[jwa][symmetric-key-serialization][a256kw-encryptdecrypt]")
{
    vector<unsigned char> cek(32, 0x7B);
    verifySymmetricKeyWrapSerializedDeserializedCombinations(JWA::KeyEncryptionAlgorithm::a256kw,
                                                             256,
                                                             cek);
}

// Content encryption tests
TEST_CASE("A128GCM_EncryptDecrypt", "[jwa][a128gcm-encryptdecrypt]")
{
    vector<unsigned char> cek(16, 0x42);                               // 128-bit key
    vector<unsigned char> iv(12, 0x01);                                // 96-bit IV for GCM
    vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    vector<unsigned char> aad = {0x41, 0x41, 0x44};                    // AAD

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());
    REQUIRE(plaintext != ciphertext);

    vector<unsigned char> decrypted = JWA::decryptContent(JWA::ContentEncryptionAlgorithm::a128gcm,
                                                          cek,
                                                          iv,
                                                          ciphertext,
                                                          aad,
                                                          tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A256GCM_EncryptDecrypt", "[jwa][a256gcm-encryptdecrypt]")
{
    vector<unsigned char> cek(32, 0x42);  // 256-bit key
    vector<unsigned char> iv(12, 0x01);
    vector<unsigned char> plaintext = {0x54, 0x65, 0x73, 0x74};  // "Test"
    vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a256gcm, cek, iv, plaintext, aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    vector<unsigned char> decrypted = JWA::decryptContent(JWA::ContentEncryptionAlgorithm::a256gcm,
                                                          cek,
                                                          iv,
                                                          ciphertext,
                                                          aad,
                                                          tag);

    REQUIRE(plaintext == decrypted);
}

TEST_CASE("A128CBC_HS256_EncryptDecrypt", "[jwa][a128cbc-hs256-encryptdecrypt]")
{
    vector<unsigned char> cek(32, 0x42);  // 256-bit key (128 for AES + 128 for HMAC)
    vector<unsigned char> iv(16, 0x01);   // 128-bit IV for CBC
    vector<unsigned char> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};
    vector<unsigned char> aad = {0x41, 0x41, 0x44};

    auto [ciphertext, tag] = JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128cbc_hs256,
                                                 cek,
                                                 iv,
                                                 plaintext,
                                                 aad);

    REQUIRE_FALSE(ciphertext.empty());
    REQUIRE_FALSE(tag.empty());

    vector<unsigned char> decrypted =
        JWA::decryptContent(JWA::ContentEncryptionAlgorithm::a128cbc_hs256,
                            cek,
                            iv,
                            ciphertext,
                            aad,
                            tag);

    REQUIRE(plaintext == decrypted);
}

// Edge cases
TEST_CASE("EmptyDataSignature", "[jwa][emptydatasignature]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string emptyStr;

    JWS jws = sign(key, JWA::SignatureAlgorithm::rs256, emptyStr);

    REQUIRE(verify(jws, key));
}

TEST_CASE("LargeDataSignature", "[jwa][largedatasignature]")
{
    JWK key = JWK::generateRSA(JWK::Use::signature, 2048);
    string largeStr(10000, 'B');

    JWS jws = sign(key, JWA::SignatureAlgorithm::rs256, largeStr);

    REQUIRE(verify(jws, key));
}

TEST_CASE("EmptyPlaintextEncryption", "[jwa][emptyplaintextencryption]")
{
    vector<unsigned char> cek(16, 0x42);
    vector<unsigned char> iv(12, 0x01);
    vector<unsigned char> plaintext;
    vector<unsigned char> aad;

    auto [ciphertext, tag] =
        JWA::encryptContent(JWA::ContentEncryptionAlgorithm::a128gcm, cek, iv, plaintext, aad);

    vector<unsigned char> decrypted = JWA::decryptContent(JWA::ContentEncryptionAlgorithm::a128gcm,
                                                          cek,
                                                          iv,
                                                          ciphertext,
                                                          aad,
                                                          tag);

    REQUIRE(plaintext == decrypted);
}

SCENARIO("JWA::signatureAlgorithmFromString nothrow returns algorithm for a known string",
         "[jwa][signaturealgorithmfromstring][nothrow]")
{
    GIVEN("a known signature algorithm string")
    {
        string alg = "HS256";

        WHEN("converting with nothrow")
        {
            auto result = JWA::signatureAlgorithmFromString(alg, std::nothrow);

            THEN("the result contains the expected algorithm")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == JWA::SignatureAlgorithm::hs256);
            }
        }
    }
}

SCENARIO("JWA::signatureAlgorithmFromString nothrow returns empty optional for an unknown string",
         "[jwa][signaturealgorithmfromstring][nothrow]")
{
    GIVEN("an unknown signature algorithm string")
    {
        string alg = "BOGUS-ALG";

        WHEN("converting with nothrow")
        {
            auto result = JWA::signatureAlgorithmFromString(alg, std::nothrow);

            THEN("the result is an empty optional")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("JWA::keyEncryptionAlgorithmFromString nothrow returns algorithm for a known string",
         "[jwa][keyencryptionalgorithmfromstring][nothrow]")
{
    GIVEN("a known key encryption algorithm string")
    {
        string alg = "RSA-OAEP";

        WHEN("converting with nothrow")
        {
            auto result = JWA::keyEncryptionAlgorithmFromString(alg, std::nothrow);

            THEN("the result contains the expected algorithm")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == JWA::KeyEncryptionAlgorithm::rsa_oaep);
            }
        }
    }
}

SCENARIO(
    "JWA::keyEncryptionAlgorithmFromString nothrow returns empty optional for an unknown string",
    "[jwa][keyencryptionalgorithmfromstring][nothrow]")
{
    GIVEN("an unknown key encryption algorithm string")
    {
        string alg = "BOGUS-KEK";

        WHEN("converting with nothrow")
        {
            auto result = JWA::keyEncryptionAlgorithmFromString(alg, std::nothrow);

            THEN("the result is an empty optional")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("JWA::contentEncryptionAlgorithmFromString nothrow returns algorithm for a known string",
         "[jwa][contentencryptionalgorithmfromstring][nothrow]")
{
    GIVEN("a known content encryption algorithm string")
    {
        string alg = "A128GCM";

        WHEN("converting with nothrow")
        {
            auto result = JWA::contentEncryptionAlgorithmFromString(alg, std::nothrow);

            THEN("the result contains the expected algorithm")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == JWA::ContentEncryptionAlgorithm::a128gcm);
            }
        }
    }
}

SCENARIO("JWA::contentEncryptionAlgorithmFromString nothrow returns empty optional for an unknown "
         "string",
         "[jwa][contentencryptionalgorithmfromstring][nothrow]")
{
    GIVEN("an unknown content encryption algorithm string")
    {
        string alg = "BOGUS-CEK";

        WHEN("converting with nothrow")
        {
            auto result = JWA::contentEncryptionAlgorithmFromString(alg, std::nothrow);

            THEN("the result is an empty optional")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}
