#include "jose/jwe.hpp"

#include <openssl/rand.h>

#include <map>
#include <sstream>
#include <stdexcept>

#include "jose/base64url.hpp"
#include "jose/json_utils.hpp"
#include "jose/jwa.hpp"
#include "jose/jwk.hpp"

namespace Vlinder {
namespace jose {

namespace {

size_t getKeySize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::A128GCM:
        case JWA::ContentEncryptionAlgorithm::A128CBC_HS256:
            return 32;  // 256 bits for A128CBC_HS256 (128 for AES + 128 for HMAC)
        case JWA::ContentEncryptionAlgorithm::A192GCM:
        case JWA::ContentEncryptionAlgorithm::A192CBC_HS384:
            return 48;  // 384 bits
        case JWA::ContentEncryptionAlgorithm::A256GCM:
        case JWA::ContentEncryptionAlgorithm::A256CBC_HS512:
            return 64;  // 512 bits for A256CBC_HS512
        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

size_t getIVSize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::A128GCM:
        case JWA::ContentEncryptionAlgorithm::A192GCM:
        case JWA::ContentEncryptionAlgorithm::A256GCM:
            return 12;  // 96 bits for GCM
        case JWA::ContentEncryptionAlgorithm::A128CBC_HS256:
        case JWA::ContentEncryptionAlgorithm::A192CBC_HS384:
        case JWA::ContentEncryptionAlgorithm::A256CBC_HS512:
            return 16;  // 128 bits for CBC
        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

}  // anonymous namespace

struct JWE::Impl
{
    std::string plaintext;
    JWA::KeyEncryptionAlgorithm keyAlgorithm = JWA::KeyEncryptionAlgorithm::RSA_OAEP;
    JWA::ContentEncryptionAlgorithm contentAlgorithm = JWA::ContentEncryptionAlgorithm::A256GCM;
    std::string kid;
    std::string typ;
    std::map<std::string, std::string> headerParams;
    std::string headerJson;
};

JWE::JWE() : impl_(std::make_unique<Impl>())
{
}

JWE::~JWE() = default;

JWE::JWE(const JWE& other) : impl_(std::make_unique<Impl>(*other.impl_))
{
}

JWE& JWE::operator=(const JWE& other)
{
    if (this != &other)
    {
        impl_ = std::make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWE::JWE(JWE&& other) noexcept = default;
JWE& JWE::operator=(JWE&& other) noexcept = default;

void JWE::setPlaintext(const std::string& plaintext)
{
    impl_->plaintext = plaintext;
}

void JWE::setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm algorithm)
{
    impl_->keyAlgorithm = algorithm;
}

void JWE::setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm algorithm)
{
    impl_->contentAlgorithm = algorithm;
}

void JWE::setKeyId(const std::string& kid)
{
    impl_->kid = kid;
}

void JWE::setType(const std::string& typ)
{
    impl_->typ = typ;
}

void JWE::setHeaderParam(const std::string& name, const std::string& value)
{
    impl_->headerParams[name] = value;
}

std::string JWE::encrypt(const JWK& key) const
{
    // Build JOSE header
    JsonValue header;
    header.setObject();
    header.set("alg", JsonValue(JWA::toString(impl_->keyAlgorithm)));
    header.set("enc", JsonValue(JWA::toString(impl_->contentAlgorithm)));

    if (!impl_->typ.empty())
    {
        header.set("typ", JsonValue(impl_->typ));
    }

    if (!impl_->kid.empty())
    {
        header.set("kid", JsonValue(impl_->kid));
    }

    // Add custom header parameters
    for (const auto& param : impl_->headerParams)
    {
        header.set(param.first, JsonValue(param.second));
    }

    std::string headerJson = header.serialize();
    std::string encodedHeader = Base64Url::encode(headerJson);

    // Generate CEK (Content Encryption Key)
    size_t cekSize = getKeySize(impl_->contentAlgorithm);
    std::vector<unsigned char> cek(cekSize);
    if (RAND_bytes(cek.data(), static_cast<int>(cekSize)) != 1)
    {
        throw std::runtime_error("Failed to generate random CEK");
    }

    // Encrypt CEK
    std::vector<unsigned char> encryptedKey;
    if (impl_->keyAlgorithm == JWA::KeyEncryptionAlgorithm::DIR)
    {
        encryptedKey.clear();  // Direct encryption uses the key directly
    }
    else
    {
        encryptedKey = JWA::encryptKey(impl_->keyAlgorithm, key, cek);
    }
    std::string encodedEncryptedKey = Base64Url::encode(encryptedKey);

    // Generate IV
    size_t ivSize = getIVSize(impl_->contentAlgorithm);
    std::vector<unsigned char> iv(ivSize);
    if (RAND_bytes(iv.data(), static_cast<int>(ivSize)) != 1)
    {
        throw std::runtime_error("Failed to generate random IV");
    }
    std::string encodedIV = Base64Url::encode(iv);

    // Prepare AAD (Additional Authenticated Data) - the encoded header
    std::vector<unsigned char> aad(encodedHeader.begin(), encodedHeader.end());

    // Encrypt content
    std::vector<unsigned char> plaintextBytes(impl_->plaintext.begin(), impl_->plaintext.end());
    auto [ciphertext, authTag] =
        JWA::encryptContent(impl_->contentAlgorithm, cek, iv, plaintextBytes, aad);

    std::string encodedCiphertext = Base64Url::encode(ciphertext);
    std::string encodedAuthTag = Base64Url::encode(authTag);

    // Return compact serialization: header.encryptedKey.iv.ciphertext.authTag
    return encodedHeader + "." + encodedEncryptedKey + "." + encodedIV + "." + encodedCiphertext +
           "." + encodedAuthTag;
}

std::string JWE::decrypt(const std::string& jwe, const JWK& key)
{
    // Split into five parts
    std::vector<std::string> parts;
    size_t start = 0;
    size_t pos = 0;

    while ((pos = jwe.find('.', start)) != std::string::npos)
    {
        parts.push_back(jwe.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(jwe.substr(start));

    if (parts.size() != 5)
    {
        throw std::runtime_error("Invalid JWE format: expected 5 parts");
    }

    std::string encodedHeader = parts[0];
    std::string encodedEncryptedKey = parts[1];
    std::string encodedIV = parts[2];
    std::string encodedCiphertext = parts[3];
    std::string encodedAuthTag = parts[4];

    // Decode header to get algorithms
    std::string headerJson = Base64Url::decodeToString(encodedHeader);
    JsonValue header = JsonValue::parse(headerJson);

    if (!header.has("alg") || !header.has("enc"))
    {
        throw std::runtime_error("JWE header missing required algorithm fields");
    }

    std::string algStr = header["alg"].asString();
    std::string encStr = header["enc"].asString();

    JWA::KeyEncryptionAlgorithm keyAlg = JWA::keyEncryptionAlgorithmFromString(algStr);
    JWA::ContentEncryptionAlgorithm contentAlg = JWA::contentEncryptionAlgorithmFromString(encStr);

    // Decrypt CEK
    std::vector<unsigned char> cek;
    if (keyAlg == JWA::KeyEncryptionAlgorithm::DIR)
    {
        // For direct encryption, derive CEK from the key
        // This is a simplified implementation
        throw std::runtime_error("DIR algorithm not yet fully implemented");
    }
    else
    {
        std::vector<unsigned char> encryptedKey = Base64Url::decode(encodedEncryptedKey);
        cek = JWA::decryptKey(keyAlg, key, encryptedKey);
    }

    // Decode other components
    std::vector<unsigned char> iv = Base64Url::decode(encodedIV);
    std::vector<unsigned char> ciphertext = Base64Url::decode(encodedCiphertext);
    std::vector<unsigned char> authTag = Base64Url::decode(encodedAuthTag);

    // Prepare AAD
    std::vector<unsigned char> aad(encodedHeader.begin(), encodedHeader.end());

    // Decrypt content
    std::vector<unsigned char> plaintext =
        JWA::decryptContent(contentAlg, cek, iv, ciphertext, aad, authTag);

    return std::string(plaintext.begin(), plaintext.end());
}

JWE JWE::parse(const std::string& jwe)
{
    // Split into five parts
    std::vector<std::string> parts;
    size_t start = 0;
    size_t pos = 0;

    while ((pos = jwe.find('.', start)) != std::string::npos)
    {
        parts.push_back(jwe.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(jwe.substr(start));

    if (parts.size() != 5)
    {
        throw std::runtime_error("Invalid JWE format: expected 5 parts");
    }

    std::string encodedHeader = parts[0];

    // Decode header
    std::string headerJson = Base64Url::decodeToString(encodedHeader);
    JsonValue header = JsonValue::parse(headerJson);

    JWE result;
    result.impl_->headerJson = headerJson;

    if (header.has("alg"))
    {
        std::string algStr = header["alg"].asString();
        result.impl_->keyAlgorithm = JWA::keyEncryptionAlgorithmFromString(algStr);
    }

    if (header.has("enc"))
    {
        std::string encStr = header["enc"].asString();
        result.impl_->contentAlgorithm = JWA::contentEncryptionAlgorithmFromString(encStr);
    }

    if (header.has("kid"))
    {
        result.impl_->kid = header["kid"].asString();
    }

    if (header.has("typ"))
    {
        result.impl_->typ = header["typ"].asString();
    }

    return result;
}

std::string JWE::getPlaintext() const
{
    return impl_->plaintext;
}

std::string JWE::getHeader() const
{
    if (!impl_->headerJson.empty())
    {
        return impl_->headerJson;
    }

    JsonValue header;
    header.setObject();
    header.set("alg", JsonValue(JWA::toString(impl_->keyAlgorithm)));
    header.set("enc", JsonValue(JWA::toString(impl_->contentAlgorithm)));

    if (!impl_->typ.empty())
    {
        header.set("typ", JsonValue(impl_->typ));
    }

    if (!impl_->kid.empty())
    {
        header.set("kid", JsonValue(impl_->kid));
    }

    for (const auto& param : impl_->headerParams)
    {
        header.set(param.first, JsonValue(param.second));
    }

    return header.serialize();
}

}  // namespace jose
}  // namespace Vlinder
