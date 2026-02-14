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
namespace JOSE {

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
    json header = json::object();
    header["alg"] = JWA::toString(impl_->keyAlgorithm);
    header["enc"] = JWA::toString(impl_->contentAlgorithm);

    if (!impl_->typ.empty())
    {
        header["typ"] = impl_->typ;
    }

    if (!impl_->kid.empty())
    {
        header["kid"] = impl_->kid;
    }

    // Add custom header parameters
    for (const auto& param : impl_->headerParams)
    {
        header[param.first] = param.second;
    }

    // Generate or use CEK (Content Encryption Key)
    std::vector<unsigned char> cek;
    std::vector<unsigned char> encryptedKey;
    std::vector<unsigned char> kekIv;  // For GCM key wrap
    std::vector<unsigned char> kekTag; // For GCM key wrap
    
    if (impl_->keyAlgorithm == JWA::KeyEncryptionAlgorithm::DIR)
    {
        // For direct encryption, use the provided key directly as the CEK
        encryptedKey.clear();  // No encrypted key field
        
        // Extract the symmetric key material from the JWK
        EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
        if (!pkey)
        {
            throw std::runtime_error("Invalid key");
        }
        
        size_t keyLen = 0;
        if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &keyLen) != 1)
        {
            throw std::runtime_error("Failed to get key length");
        }
        
        cek.resize(keyLen);
        if (EVP_PKEY_get_raw_private_key(pkey, cek.data(), &keyLen) != 1)
        {
            throw std::runtime_error("Failed to get key data");
        }
    }
    else
    {
        // Generate random CEK and encrypt it with the key
        size_t cekSize = getKeySize(impl_->contentAlgorithm);
        cek.resize(cekSize);
        if (RAND_bytes(cek.data(), static_cast<int>(cekSize)) != 1)
        {
            throw std::runtime_error("Failed to generate random CEK");
        }
        
        // Check if this is a GCM key wrap algorithm
        bool isGcmKw = (impl_->keyAlgorithm == JWA::KeyEncryptionAlgorithm::A128GCMKW ||
                        impl_->keyAlgorithm == JWA::KeyEncryptionAlgorithm::A192GCMKW ||
                        impl_->keyAlgorithm == JWA::KeyEncryptionAlgorithm::A256GCMKW);
        
        if (isGcmKw)
        {
            encryptedKey = JWA::encryptKey(impl_->keyAlgorithm, key, cek, &kekIv, &kekTag);
        }
        else
        {
            encryptedKey = JWA::encryptKey(impl_->keyAlgorithm, key, cek);
        }
    }
    
    // Add GCM key wrap IV and tag to header if present
    if (!kekIv.empty())
    {
        header["iv"] = Base64Url::encode(kekIv);
    }
    if (!kekTag.empty())
    {
        header["tag"] = Base64Url::encode(kekTag);
    }
    
    // Now encode the header with all fields
    std::string headerJson = header.dump();
    std::string encodedHeader = Base64Url::encode(headerJson);
    
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
    json header = json::parse(headerJson);

    if (!header.contains("alg") || !header.contains("enc"))
    {
        throw std::runtime_error("JWE header missing required algorithm fields");
    }

    std::string algStr = header["alg"].get<std::string>();
    std::string encStr = header["enc"].get<std::string>();

    JWA::KeyEncryptionAlgorithm keyAlg = JWA::keyEncryptionAlgorithmFromString(algStr);
    JWA::ContentEncryptionAlgorithm contentAlg = JWA::contentEncryptionAlgorithmFromString(encStr);

    // Decrypt CEK
    std::vector<unsigned char> cek;
    if (keyAlg == JWA::KeyEncryptionAlgorithm::DIR)
    {
        // For direct encryption, use the provided key directly as the CEK
        EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
        if (!pkey)
        {
            throw std::runtime_error("Invalid key");
        }
        
        size_t keyLen = 0;
        if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &keyLen) != 1)
        {
            throw std::runtime_error("Failed to get key length");
        }
        
        cek.resize(keyLen);
        if (EVP_PKEY_get_raw_private_key(pkey, cek.data(), &keyLen) != 1)
        {
            throw std::runtime_error("Failed to get key data");
        }
    }
    else
    {
        std::vector<unsigned char> encryptedKey = Base64Url::decode(encodedEncryptedKey);
        
        // Check for GCM key wrap IV and tag in header
        std::vector<unsigned char> kekIv;
        std::vector<unsigned char> kekTag;
        
        if (header.contains("iv"))
        {
            kekIv = Base64Url::decode(header["iv"].get<std::string>());
        }
        if (header.contains("tag"))
        {
            kekTag = Base64Url::decode(header["tag"].get<std::string>());
        }
        
        // Pass IV and tag if present (for GCM key wrap)
        if (!kekIv.empty() && !kekTag.empty())
        {
            cek = JWA::decryptKey(keyAlg, key, encryptedKey, &kekIv, &kekTag);
        }
        else
        {
            cek = JWA::decryptKey(keyAlg, key, encryptedKey);
        }
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
    json header = json::parse(headerJson);

    JWE result;
    result.impl_->headerJson = headerJson;

    if (header.contains("alg"))
    {
        std::string algStr = header["alg"].get<std::string>();
        result.impl_->keyAlgorithm = JWA::keyEncryptionAlgorithmFromString(algStr);
    }

    if (header.contains("enc"))
    {
        std::string encStr = header["enc"].get<std::string>();
        result.impl_->contentAlgorithm = JWA::contentEncryptionAlgorithmFromString(encStr);
    }

    if (header.contains("kid"))
    {
        result.impl_->kid = header["kid"].get<std::string>();
    }

    if (header.contains("typ"))
    {
        result.impl_->typ = header["typ"].get<std::string>();
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

    json header = json::object();
    header["alg"] = JWA::toString(impl_->keyAlgorithm);
    header["enc"] = JWA::toString(impl_->contentAlgorithm);

    if (!impl_->typ.empty())
    {
        header["typ"] = impl_->typ;
    }

    if (!impl_->kid.empty())
    {
        header["kid"] = impl_->kid;
    }

    for (const auto& param : impl_->headerParams)
    {
        header[param.first] = param.second;
    }

    return header.dump();
}

}  // namespace JOSE
}  // namespace Vlinder
