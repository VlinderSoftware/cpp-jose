#include <catch2/catch_test_macros.hpp>

#include <string>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;


// Basic JWE creation tests
TEST_CASE("JWE_CreateSimpleJWE", "[jwe][createsimplejwe]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("test plaintext");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);
    REQUIRE_FALSE(token.empty());

    // Should have 5 parts separated by dots
    int dotCount = 0;
    for (char c : token)
    {
        if (c == '.')
            dotCount++;
    }
    REQUIRE(4 == dotCount);  // 5 parts = 4 dots
}

TEST_CASE("JWE_EncryptDecryptRSA_OAEP_A128GCM", "[jwe][encryptdecryptrsa-oaep-a128gcm]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    std::string plaintext = "This is a secret message";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptRSA_OAEP_A256GCM", "[jwe][encryptdecryptrsa-oaep-a256gcm]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    std::string plaintext = "Secret data with A256GCM";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptRSA_OAEP_256_A128GCM", "[jwe][encryptdecryptrsa-oaep-256-a128gcm]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    std::string plaintext = "Testing RSA-OAEP-256";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep_256);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptA128KW_A128GCM", "[jwe][encryptdecrypta128kw-a128gcm]")
{
    JWK key = JWK::generateOct(128);

    JWE jwe;
    std::string plaintext = "AES Key Wrap test";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::a128kw);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptA256KW_A256GCM", "[jwe][encryptdecrypta256kw-a256gcm]")
{
    JWK key = JWK::generateOct(256);

    JWE jwe;
    std::string plaintext = "A256KW with A256GCM";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::a256kw);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptDIR_A128GCM", "[jwe][encryptdecryptdir-a128gcm]")
{
    JWK key = JWK::generateOct(128);

    JWE jwe;
    std::string plaintext = "Direct encryption test";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::dir);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptA128CBC_HS256", "[jwe][encryptdecrypta128cbc-hs256]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    std::string plaintext = "Testing CBC mode";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128cbc_hs256);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_EncryptDecryptA256CBC_HS512", "[jwe][encryptdecrypta256cbc-hs512]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    std::string plaintext = "Testing A256CBC-HS512";
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256cbc_hs512);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

// Header and metadata tests
TEST_CASE("JWE_SetKeyId", "[jwe][setkeyid]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);
    jwe.setKeyID("my-key-id");

    std::string token = jwe.encrypt(key);

    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();

    REQUIRE(std::string::npos != header.find("my-key-id"));
}

TEST_CASE("JWE_SetType", "[jwe][settype]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);
    jwe.setType("JWT");

    std::string token = jwe.encrypt(key);

    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();

    REQUIRE(std::string::npos != header.find("JWT"));
}

TEST_CASE("JWE_SetCustomHeaderParam", "[jwe][setcustomheaderparam]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);
    jwe.setHeaderParam("custom", "value");

    std::string token = jwe.encrypt(key);

    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();

    REQUIRE(std::string::npos != header.find("custom"));
    REQUIRE(std::string::npos != header.find("value"));
}

TEST_CASE("JWE_GetHeader", "[jwe][getheader]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("test");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();

    REQUIRE_FALSE(header.empty());
    REQUIRE(std::string::npos != header.find("alg"));
    REQUIRE(std::string::npos != header.find("enc"));
}

// Parsing tests
TEST_CASE("JWE_ParseJWE", "[jwe][parsejwe]")
{
    JWK key = JWK::generateRSA(2048);

    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);
    original.setKeyID("key-123");

    std::string token = original.encrypt(key);

    JWE parsed = JWE::parse(token);
    std::string header = parsed.getHeader();

    REQUIRE(std::string::npos != header.find("key-123"));
}

// Wrong key tests
TEST_CASE("JWE_DecryptWithWrongKeyFails", "[jwe][decryptwithwrongkeyfails]")
{
    JWK key1 = JWK::generateRSA(2048);
    JWK key2 = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("secret");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key1);

    REQUIRE_THROWS_AS(JWE::decrypt(token, key2), std::exception);
}

TEST_CASE("JWE_SymmetricWrongKeyFails", "[jwe][symmetricwrongkeyfails]")
{
    JWK key1 = JWK::generateOct(256);
    JWK key2 = JWK::generateOct(256);

    JWE jwe;
    jwe.setPlaintext("secret");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::a256kw);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a256gcm);

    std::string token = jwe.encrypt(key1);

    REQUIRE_THROWS_AS(JWE::decrypt(token, key2), std::exception);
}

// Tampering tests
TEST_CASE("JWE_TamperedCiphertextFails", "[jwe][tamperedciphertextfails]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("original");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    // Tamper with ciphertext part (4th component)
    size_t dot1 = token.find('.');
    size_t dot2 = token.find('.', dot1 + 1);
    size_t dot3 = token.find('.', dot2 + 1);
    size_t dot4 = token.find('.', dot3 + 1);

    if (dot3 != std::string::npos && dot4 != std::string::npos && dot3 + 1 < dot4)
    {
        token[dot3 + 1] = (token[dot3 + 1] == 'A') ? 'B' : 'A';
    }

    REQUIRE_THROWS_AS(JWE::decrypt(token, key), std::exception);
}

// Copy and move semantics
TEST_CASE("JWE_CopyConstructor", "[jwe][copyconstructor]")
{
    JWE original;
    original.setPlaintext("test");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    JWE copy(original);
    REQUIRE(original.getPlaintext() == copy.getPlaintext());
}

TEST_CASE("JWE_CopyAssignment", "[jwe][copyassignment]")
{
    JWE original;
    original.setPlaintext("test");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    JWE copy = original;
    REQUIRE(original.getPlaintext() == copy.getPlaintext());
}

TEST_CASE("JWE_MoveConstructor", "[jwe][moveconstructor]")
{
    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    JWE moved(std::move(original));
    REQUIRE("test plaintext" == moved.getPlaintext());
}

TEST_CASE("JWE_MoveAssignment", "[jwe][moveassignment]")
{
    JWE original;
    original.setPlaintext("test plaintext");
    original.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    original.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    JWE moved = std::move(original);
    REQUIRE("test plaintext" == moved.getPlaintext());
}

// Edge cases
TEST_CASE("JWE_EmptyPlaintext", "[jwe][emptyplaintext]")
{
    JWK key = JWK::generateRSA(2048);

    JWE jwe;
    jwe.setPlaintext("");
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);
    REQUIRE_FALSE(token.empty());

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE("" == decrypted);
}

TEST_CASE("JWE_LargePlaintext", "[jwe][largeplaintext]")
{
    JWK key = JWK::generateRSA(2048);

    std::string largePlaintext(10000, 'X');

    JWE jwe;
    jwe.setPlaintext(largePlaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(largePlaintext == decrypted);
}

TEST_CASE("JWE_PlaintextWithSpecialCharacters", "[jwe][plaintextwithspecialcharacters]")
{
    JWK key = JWK::generateRSA(2048);

    std::string plaintext = "Special: \n\t\r\"'{}[]<>!@#$%^&*()";

    JWE jwe;
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_BinaryPlaintext", "[jwe][binaryplaintext]")
{
    JWK key = JWK::generateRSA(2048);

    std::string plaintext;
    for (int i = 0; i < 256; i++)
    {
        plaintext += static_cast<char>(i);
    }

    JWE jwe;
    jwe.setPlaintext(plaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(plaintext == decrypted);
}

TEST_CASE("JWE_JSONPlaintext", "[jwe][jsonplaintext]")
{
    JWK key = JWK::generateRSA(2048);

    std::string jsonPlaintext = R"({
        "user": "john",
        "role": "admin",
        "permissions": ["read", "write", "delete"]
    })";

    JWE jwe;
    jwe.setPlaintext(jsonPlaintext);
    jwe.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token = jwe.encrypt(key);

    std::string decrypted = JWE::decrypt(token, key);
    REQUIRE(jsonPlaintext == decrypted);
}

TEST_CASE("JWE_MultipleEncryptionsSamePlaintext", "[jwe][multipleencryptionssameplaintext]")
{
    JWK key = JWK::generateRSA(2048);
    std::string plaintext = "same plaintext";

    JWE jwe1;
    jwe1.setPlaintext(plaintext);
    jwe1.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe1.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    JWE jwe2;
    jwe2.setPlaintext(plaintext);
    jwe2.setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm::rsa_oaep);
    jwe2.setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm::a128gcm);

    std::string token1 = jwe1.encrypt(key);
    std::string token2 = jwe2.encrypt(key);

    // Tokens should be different due to random IV/CEK
    REQUIRE(token1 != token2);

    // But both should decrypt to same plaintext
    REQUIRE(plaintext == JWE::decrypt(token1, key));
    REQUIRE(plaintext == JWE::decrypt(token2, key));
}
