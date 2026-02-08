#include "jose/jwa.hpp"
#include "jose/jwk.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>
#include <map>

namespace Vlinder
{
namespace jose
{

namespace
{

std::string getOpenSSLError()
{
    unsigned long err = ERR_get_error();
    if (err == 0)
    {
        return "Unknown error";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

const EVP_MD* getMD(JWA::SignatureAlgorithm alg)
{
    switch (alg)
    {
        case JWA::SignatureAlgorithm::HS256:
        case JWA::SignatureAlgorithm::RS256:
        case JWA::SignatureAlgorithm::ES256:
        case JWA::SignatureAlgorithm::PS256:
            return EVP_sha256();
        case JWA::SignatureAlgorithm::HS384:
        case JWA::SignatureAlgorithm::RS384:
        case JWA::SignatureAlgorithm::ES384:
        case JWA::SignatureAlgorithm::PS384:
            return EVP_sha384();
        case JWA::SignatureAlgorithm::HS512:
        case JWA::SignatureAlgorithm::RS512:
        case JWA::SignatureAlgorithm::ES512:
        case JWA::SignatureAlgorithm::PS512:
            return EVP_sha512();
        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

std::vector<unsigned char> hmacSign(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    size_t keyLen = 0;
    unsigned char* keyData = nullptr;
    
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &keyLen) != 1)
    {
        throw std::runtime_error("Failed to get key length: " + getOpenSSLError());
    }
    
    keyData = new unsigned char[keyLen];
    if (EVP_PKEY_get_raw_private_key(pkey, keyData, &keyLen) != 1)
    {
        delete[] keyData;
        throw std::runtime_error("Failed to get key data: " + getOpenSSLError());
    }

    unsigned int sigLen;
    std::vector<unsigned char> signature(EVP_MD_size(md));
    
    if (!HMAC(md, keyData, keyLen, data.data(), data.size(), signature.data(), &sigLen))
    {
        delete[] keyData;
        throw std::runtime_error("HMAC signing failed: " + getOpenSSLError());
    }
    
    delete[] keyData;
    signature.resize(sigLen);
    return signature;
}

bool hmacVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature)
{
    std::vector<unsigned char> expectedSig = hmacSign(md, key, data);
    
    if (expectedSig.size() != signature.size())
    {
        return false;
    }
    
    return CRYPTO_memcmp(expectedSig.data(), signature.data(), signature.size()) == 0;
}
std::vector<unsigned char> rsaSign(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data, bool usePSS)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw std::runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    EVP_PKEY_CTX* pctx = nullptr;
    
    if (EVP_DigestSignInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize signing: " + getOpenSSLError());
    }

    if (usePSS)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to set PSS padding: " + getOpenSSLError());
        }
        
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to set PSS salt length: " + getOpenSSLError());
        }
    }

    size_t sigLen;
    if (EVP_DigestSign(mdctx, nullptr, &sigLen, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    std::vector<unsigned char> signature(sigLen);
    if (EVP_DigestSign(mdctx, signature.data(), &sigLen, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    signature.resize(sigLen);
    return signature;
}

bool rsaVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature, bool usePSS)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw std::runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    EVP_PKEY_CTX* pctx = nullptr;
    
    if (EVP_DigestVerifyInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize verification: " + getOpenSSLError());
    }

    if (usePSS)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to set PSS padding: " + getOpenSSLError());
        }
        
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to set PSS salt length: " + getOpenSSLError());
        }
    }

    int result = EVP_DigestVerify(mdctx, signature.data(), signature.size(), data.data(), data.size());
    
    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

std::vector<unsigned char> ecdsaSign(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw std::runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    if (EVP_DigestSignInit(mdctx, nullptr, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize signing: " + getOpenSSLError());
    }

    size_t sigLen;
    if (EVP_DigestSign(mdctx, nullptr, &sigLen, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    std::vector<unsigned char> derSignature(sigLen);
    if (EVP_DigestSign(mdctx, derSignature.data(), &sigLen, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    derSignature.resize(sigLen);
    
    const unsigned char* p = derSignature.data();
    ECDSA_SIG* ecdsaSig = d2i_ECDSA_SIG(nullptr, &p, derSignature.size());
    if (!ecdsaSig)
    {
        throw std::runtime_error("Failed to parse ECDSA signature: " + getOpenSSLError());
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(ecdsaSig, &r, &s);

    size_t keySize = EVP_MD_size(md);
    std::vector<unsigned char> signature(2 * keySize, 0);
    
    BN_bn2binpad(r, signature.data(), keySize);
    BN_bn2binpad(s, signature.data() + keySize, keySize);

    ECDSA_SIG_free(ecdsaSig);
    return signature;
}

bool ecdsaVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature)
{
    if (signature.size() % 2 != 0)
    {
        return false;
    }

    size_t keySize = signature.size() / 2;
    
    BIGNUM* r = BN_bin2bn(signature.data(), keySize, nullptr);
    BIGNUM* s = BN_bin2bn(signature.data() + keySize, keySize, nullptr);
    
    if (!r || !s)
    {
        if (r) BN_free(r);
        if (s) BN_free(s);
        return false;
    }

    ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
    if (!ecdsaSig)
    {
        BN_free(r);
        BN_free(s);
        return false;
    }

    ECDSA_SIG_set0(ecdsaSig, r, s);

    unsigned char* derSig = nullptr;
    int derLen = i2d_ECDSA_SIG(ecdsaSig, &derSig);
    
    if (derLen <= 0)
    {
        ECDSA_SIG_free(ecdsaSig);
        return false;
    }

    std::vector<unsigned char> derSignature(derSig, derSig + derLen);
    OPENSSL_free(derSig);
    ECDSA_SIG_free(ecdsaSig);

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        return false;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        return false;
    }

    if (EVP_DigestVerifyInit(mdctx, nullptr, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    int result = EVP_DigestVerify(mdctx, derSignature.data(), derSignature.size(), data.data(), data.size());
    
    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

std::vector<unsigned char> rsaEncrypt(const JWK& key, const std::vector<unsigned char>& plaintext, int padding, const EVP_MD* md = nullptr)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create context: " + getOpenSSLError());
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set padding: " + getOpenSSLError());
    }

    if (padding == RSA_PKCS1_OAEP_PADDING && md)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set OAEP MD: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set MGF1 MD: " + getOpenSSLError());
        }
    }

    size_t outLen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(outLen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    ciphertext.resize(outLen);
    return ciphertext;
}

std::vector<unsigned char> rsaDecrypt(const JWK& key, const std::vector<unsigned char>& ciphertext, int padding, const EVP_MD* md = nullptr)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create context: " + getOpenSSLError());
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set padding: " + getOpenSSLError());
    }

    if (padding == RSA_PKCS1_OAEP_PADDING && md)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set OAEP MD: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set MGF1 MD: " + getOpenSSLError());
        }
    }

    size_t outLen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(outLen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen, ciphertext.data(), ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    plaintext.resize(outLen);
    return plaintext;
}

std::vector<unsigned char> aesKeyWrap(const std::vector<unsigned char>& kek, const std::vector<unsigned char>& plaintext)
{
    AES_KEY wrapKey;
    if (AES_set_encrypt_key(kek.data(), kek.size() * 8, &wrapKey) < 0)
    {
        throw std::runtime_error("Failed to set AES key: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 8);
    
    int outLen = AES_wrap_key(&wrapKey, nullptr, ciphertext.data(), plaintext.data(), plaintext.size());
    
    if (outLen <= 0)
    {
        throw std::runtime_error("AES key wrap failed: " + getOpenSSLError());
    }

    ciphertext.resize(outLen);
    return ciphertext;
}

std::vector<unsigned char> aesKeyUnwrap(const std::vector<unsigned char>& kek, const std::vector<unsigned char>& ciphertext)
{
    AES_KEY unwrapKey;
    if (AES_set_decrypt_key(kek.data(), kek.size() * 8, &unwrapKey) < 0)
    {
        throw std::runtime_error("Failed to set AES key: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    
    int outLen = AES_unwrap_key(&unwrapKey, nullptr, plaintext.data(), ciphertext.data(), ciphertext.size());
    
    if (outLen <= 0)
    {
        throw std::runtime_error("AES key unwrap failed: " + getOpenSSLError());
    }

    plaintext.resize(outLen);
    return plaintext;
}

std::vector<unsigned char> aesGcmKeyWrap(const std::vector<unsigned char>& kek, const std::vector<unsigned char>& plaintext, std::vector<unsigned char>& iv, std::vector<unsigned char>& tag)
{
    if (iv.empty())
    {
        iv.resize(12);
        if (RAND_bytes(iv.data(), iv.size()) != 1)
        {
            throw std::runtime_error("Failed to generate IV: " + getOpenSSLError());
        }
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER* cipher = nullptr;
    switch (kek.size())
    {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Invalid key size for AES-GCM");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, kek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> aesGcmKeyUnwrap(const std::vector<unsigned char>& kek, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER* cipher = nullptr;
    switch (kek.size())
    {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Invalid key size for AES-GCM");
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, kek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintextLen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed (authentication failed): " + getOpenSSLError());
    }

    plaintextLen += len;
    plaintext.resize(plaintextLen);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> aesCbcHmacEncrypt(
    const EVP_CIPHER* cipher, 
    const EVP_MD* md,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad)
{
    size_t keyLen = cek.size() / 2;
    std::vector<unsigned char> macKey(cek.begin(), cek.begin() + keyLen);
    std::vector<unsigned char> encKey(cek.begin() + keyLen, cek.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, encKey.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(cipher));
    int len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> al(8);
    size_t aadBits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aadBits & 0xFF;
        aadBits >>= 8;
    }

    std::vector<unsigned char> macData;
    macData.insert(macData.end(), aad.begin(), aad.end());
    macData.insert(macData.end(), iv.begin(), iv.end());
    macData.insert(macData.end(), ciphertext.begin(), ciphertext.end());
    macData.insert(macData.end(), al.begin(), al.end());

    unsigned int macLen;
    std::vector<unsigned char> mac(EVP_MD_size(md));
    
    if (!HMAC(md, macKey.data(), macKey.size(), macData.data(), macData.size(), mac.data(), &macLen))
    {
        throw std::runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    std::vector<unsigned char> tag(mac.begin(), mac.begin() + keyLen);

    return {ciphertext, tag};
}

std::vector<unsigned char> aesCbcHmacDecrypt(
    const EVP_CIPHER* cipher, 
    const EVP_MD* md,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag)
{
    size_t keyLen = cek.size() / 2;
    std::vector<unsigned char> macKey(cek.begin(), cek.begin() + keyLen);
    std::vector<unsigned char> encKey(cek.begin() + keyLen, cek.end());

    std::vector<unsigned char> al(8);
    size_t aadBits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aadBits & 0xFF;
        aadBits >>= 8;
    }

    std::vector<unsigned char> macData;
    macData.insert(macData.end(), aad.begin(), aad.end());
    macData.insert(macData.end(), iv.begin(), iv.end());
    macData.insert(macData.end(), ciphertext.begin(), ciphertext.end());
    macData.insert(macData.end(), al.begin(), al.end());

    unsigned int macLen;
    std::vector<unsigned char> mac(EVP_MD_size(md));
    
    if (!HMAC(md, macKey.data(), macKey.size(), macData.data(), macData.size(), mac.data(), &macLen))
    {
        throw std::runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    std::vector<unsigned char> expectedTag(mac.begin(), mac.begin() + keyLen);

    if (expectedTag.size() != tag.size() || CRYPTO_memcmp(expectedTag.data(), tag.data(), tag.size()) != 0)
    {
        throw std::runtime_error("Authentication tag verification failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, encKey.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int len;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintextLen = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed: " + getOpenSSLError());
    }

    plaintextLen += len;
    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> aesGcmEncrypt(
    const EVP_CIPHER* cipher,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    int len;
    
    if (!aad.empty())
    {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to process AAD: " + getOpenSSLError());
        }
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);

    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return {ciphertext, tag};
}

std::vector<unsigned char> aesGcmDecrypt(
    const EVP_CIPHER* cipher,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    int len;
    
    if (!aad.empty())
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to process AAD: " + getOpenSSLError());
        }
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintextLen = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed (authentication failed): " + getOpenSSLError());
    }

    plaintextLen += len;
    plaintext.resize(plaintextLen);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

}

std::vector<unsigned char> JWA::sign(
    SignatureAlgorithm algorithm,
    const JWK& key,
    const std::vector<unsigned char>& data)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::HS256:
        case SignatureAlgorithm::HS384:
        case SignatureAlgorithm::HS512:
            return hmacSign(getMD(algorithm), key, data);
            
        case SignatureAlgorithm::RS256:
        case SignatureAlgorithm::RS384:
        case SignatureAlgorithm::RS512:
            return rsaSign(getMD(algorithm), key, data, false);
            
        case SignatureAlgorithm::ES256:
        case SignatureAlgorithm::ES384:
        case SignatureAlgorithm::ES512:
            return ecdsaSign(getMD(algorithm), key, data);
            
        case SignatureAlgorithm::PS256:
        case SignatureAlgorithm::PS384:
        case SignatureAlgorithm::PS512:
            return rsaSign(getMD(algorithm), key, data, true);
            
        case SignatureAlgorithm::None:
            return std::vector<unsigned char>();
            
        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

bool JWA::verify(
    SignatureAlgorithm algorithm,
    const JWK& key,
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& signature)
{
    if (algorithm == SignatureAlgorithm::None)
    {
        return signature.empty();
    }

    switch (algorithm)
    {
        case SignatureAlgorithm::HS256:
        case SignatureAlgorithm::HS384:
        case SignatureAlgorithm::HS512:
            return hmacVerify(getMD(algorithm), key, data, signature);
            
        case SignatureAlgorithm::RS256:
        case SignatureAlgorithm::RS384:
        case SignatureAlgorithm::RS512:
            return rsaVerify(getMD(algorithm), key, data, signature, false);
            
        case SignatureAlgorithm::ES256:
        case SignatureAlgorithm::ES384:
        case SignatureAlgorithm::ES512:
            return ecdsaVerify(getMD(algorithm), key, data, signature);
            
        case SignatureAlgorithm::PS256:
        case SignatureAlgorithm::PS384:
        case SignatureAlgorithm::PS512:
            return rsaVerify(getMD(algorithm), key, data, signature, true);
            
        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

std::vector<unsigned char> JWA::encryptKey(
    KeyEncryptionAlgorithm algorithm,
    const JWK& key,
    const std::vector<unsigned char>& cek)
{
    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::RSA1_5:
            return rsaEncrypt(key, cek, RSA_PKCS1_PADDING);
            
        case KeyEncryptionAlgorithm::RSA_OAEP:
            return rsaEncrypt(key, cek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());
            
        case KeyEncryptionAlgorithm::RSA_OAEP_256:
            return rsaEncrypt(key, cek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());
            
        case KeyEncryptionAlgorithm::A128KW:
        case KeyEncryptionAlgorithm::A192KW:
        case KeyEncryptionAlgorithm::A256KW:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kekLen = 0;
            unsigned char* kekData = nullptr;
            
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kekLen) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }
            
            kekData = new unsigned char[kekLen];
            if (EVP_PKEY_get_raw_private_key(pkey, kekData, &kekLen) != 1)
            {
                delete[] kekData;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kekData, kekData + kekLen);
            delete[] kekData;
            
            return aesKeyWrap(kek, cek);
        }
        
        case KeyEncryptionAlgorithm::DIR:
            return cek;
            
        case KeyEncryptionAlgorithm::A128GCMKW:
        case KeyEncryptionAlgorithm::A192GCMKW:
        case KeyEncryptionAlgorithm::A256GCMKW:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kekLen = 0;
            unsigned char* kekData = nullptr;
            
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kekLen) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }
            
            kekData = new unsigned char[kekLen];
            if (EVP_PKEY_get_raw_private_key(pkey, kekData, &kekLen) != 1)
            {
                delete[] kekData;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kekData, kekData + kekLen);
            delete[] kekData;
            
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            return aesGcmKeyWrap(kek, cek, iv, tag);
        }
        
        case KeyEncryptionAlgorithm::ECDH_ES:
            throw std::runtime_error("ECDH-ES not yet implemented");
            
        default:
            throw std::runtime_error("Unsupported key encryption algorithm");
    }
}

std::vector<unsigned char> JWA::decryptKey(
    KeyEncryptionAlgorithm algorithm,
    const JWK& key,
    const std::vector<unsigned char>& encryptedCek)
{
    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::RSA1_5:
            return rsaDecrypt(key, encryptedCek, RSA_PKCS1_PADDING);
            
        case KeyEncryptionAlgorithm::RSA_OAEP:
            return rsaDecrypt(key, encryptedCek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());
            
        case KeyEncryptionAlgorithm::RSA_OAEP_256:
            return rsaDecrypt(key, encryptedCek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());
            
        case KeyEncryptionAlgorithm::A128KW:
        case KeyEncryptionAlgorithm::A192KW:
        case KeyEncryptionAlgorithm::A256KW:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kekLen = 0;
            unsigned char* kekData = nullptr;
            
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kekLen) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }
            
            kekData = new unsigned char[kekLen];
            if (EVP_PKEY_get_raw_private_key(pkey, kekData, &kekLen) != 1)
            {
                delete[] kekData;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kekData, kekData + kekLen);
            delete[] kekData;
            
            return aesKeyUnwrap(kek, encryptedCek);
        }
        
        case KeyEncryptionAlgorithm::DIR:
            return encryptedCek;
            
        case KeyEncryptionAlgorithm::ECDH_ES:
            throw std::runtime_error("ECDH-ES not yet implemented");
            
        default:
            throw std::runtime_error("Unsupported key encryption algorithm");
    }
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> JWA::encryptContent(
    ContentEncryptionAlgorithm algorithm,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad)
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::A128CBC_HS256:
            return aesCbcHmacEncrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, plaintext, aad);
            
        case ContentEncryptionAlgorithm::A192CBC_HS384:
            return aesCbcHmacEncrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, plaintext, aad);
            
        case ContentEncryptionAlgorithm::A256CBC_HS512:
            return aesCbcHmacEncrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, plaintext, aad);
            
        case ContentEncryptionAlgorithm::A128GCM:
            return aesGcmEncrypt(EVP_aes_128_gcm(), cek, iv, plaintext, aad);
            
        case ContentEncryptionAlgorithm::A192GCM:
            return aesGcmEncrypt(EVP_aes_192_gcm(), cek, iv, plaintext, aad);
            
        case ContentEncryptionAlgorithm::A256GCM:
            return aesGcmEncrypt(EVP_aes_256_gcm(), cek, iv, plaintext, aad);
            
        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

std::vector<unsigned char> JWA::decryptContent(
    ContentEncryptionAlgorithm algorithm,
    const std::vector<unsigned char>& cek,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag)
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::A128CBC_HS256:
            return aesCbcHmacDecrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, ciphertext, aad, tag);
            
        case ContentEncryptionAlgorithm::A192CBC_HS384:
            return aesCbcHmacDecrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, ciphertext, aad, tag);
            
        case ContentEncryptionAlgorithm::A256CBC_HS512:
            return aesCbcHmacDecrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, ciphertext, aad, tag);
            
        case ContentEncryptionAlgorithm::A128GCM:
            return aesGcmDecrypt(EVP_aes_128_gcm(), cek, iv, ciphertext, aad, tag);
            
        case ContentEncryptionAlgorithm::A192GCM:
            return aesGcmDecrypt(EVP_aes_192_gcm(), cek, iv, ciphertext, aad, tag);
            
        case ContentEncryptionAlgorithm::A256GCM:
            return aesGcmDecrypt(EVP_aes_256_gcm(), cek, iv, ciphertext, aad, tag);
            
        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

std::string JWA::toString(SignatureAlgorithm alg)
{
    static const std::map<SignatureAlgorithm, std::string> algMap = {
        {SignatureAlgorithm::HS256, "HS256"},
        {SignatureAlgorithm::HS384, "HS384"},
        {SignatureAlgorithm::HS512, "HS512"},
        {SignatureAlgorithm::RS256, "RS256"},
        {SignatureAlgorithm::RS384, "RS384"},
        {SignatureAlgorithm::RS512, "RS512"},
        {SignatureAlgorithm::ES256, "ES256"},
        {SignatureAlgorithm::ES384, "ES384"},
        {SignatureAlgorithm::ES512, "ES512"},
        {SignatureAlgorithm::PS256, "PS256"},
        {SignatureAlgorithm::PS384, "PS384"},
        {SignatureAlgorithm::PS512, "PS512"},
        {SignatureAlgorithm::None, "none"}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown signature algorithm");
}

std::string JWA::toString(KeyEncryptionAlgorithm alg)
{
    static const std::map<KeyEncryptionAlgorithm, std::string> algMap = {
        {KeyEncryptionAlgorithm::RSA1_5, "RSA1_5"},
        {KeyEncryptionAlgorithm::RSA_OAEP, "RSA-OAEP"},
        {KeyEncryptionAlgorithm::RSA_OAEP_256, "RSA-OAEP-256"},
        {KeyEncryptionAlgorithm::A128KW, "A128KW"},
        {KeyEncryptionAlgorithm::A192KW, "A192KW"},
        {KeyEncryptionAlgorithm::A256KW, "A256KW"},
        {KeyEncryptionAlgorithm::DIR, "dir"},
        {KeyEncryptionAlgorithm::ECDH_ES, "ECDH-ES"},
        {KeyEncryptionAlgorithm::A128GCMKW, "A128GCMKW"},
        {KeyEncryptionAlgorithm::A192GCMKW, "A192GCMKW"},
        {KeyEncryptionAlgorithm::A256GCMKW, "A256GCMKW"}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown key encryption algorithm");
}

std::string JWA::toString(ContentEncryptionAlgorithm alg)
{
    static const std::map<ContentEncryptionAlgorithm, std::string> algMap = {
        {ContentEncryptionAlgorithm::A128CBC_HS256, "A128CBC-HS256"},
        {ContentEncryptionAlgorithm::A192CBC_HS384, "A192CBC-HS384"},
        {ContentEncryptionAlgorithm::A256CBC_HS512, "A256CBC-HS512"},
        {ContentEncryptionAlgorithm::A128GCM, "A128GCM"},
        {ContentEncryptionAlgorithm::A192GCM, "A192GCM"},
        {ContentEncryptionAlgorithm::A256GCM, "A256GCM"}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown content encryption algorithm");
}

JWA::SignatureAlgorithm JWA::signatureAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, SignatureAlgorithm> algMap = {
        {"HS256", SignatureAlgorithm::HS256},
        {"HS384", SignatureAlgorithm::HS384},
        {"HS512", SignatureAlgorithm::HS512},
        {"RS256", SignatureAlgorithm::RS256},
        {"RS384", SignatureAlgorithm::RS384},
        {"RS512", SignatureAlgorithm::RS512},
        {"ES256", SignatureAlgorithm::ES256},
        {"ES384", SignatureAlgorithm::ES384},
        {"ES512", SignatureAlgorithm::ES512},
        {"PS256", SignatureAlgorithm::PS256},
        {"PS384", SignatureAlgorithm::PS384},
        {"PS512", SignatureAlgorithm::PS512},
        {"none", SignatureAlgorithm::None}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown signature algorithm: " + alg);
}

JWA::KeyEncryptionAlgorithm JWA::keyEncryptionAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, KeyEncryptionAlgorithm> algMap = {
        {"RSA1_5", KeyEncryptionAlgorithm::RSA1_5},
        {"RSA-OAEP", KeyEncryptionAlgorithm::RSA_OAEP},
        {"RSA-OAEP-256", KeyEncryptionAlgorithm::RSA_OAEP_256},
        {"A128KW", KeyEncryptionAlgorithm::A128KW},
        {"A192KW", KeyEncryptionAlgorithm::A192KW},
        {"A256KW", KeyEncryptionAlgorithm::A256KW},
        {"dir", KeyEncryptionAlgorithm::DIR},
        {"ECDH-ES", KeyEncryptionAlgorithm::ECDH_ES},
        {"A128GCMKW", KeyEncryptionAlgorithm::A128GCMKW},
        {"A192GCMKW", KeyEncryptionAlgorithm::A192GCMKW},
        {"A256GCMKW", KeyEncryptionAlgorithm::A256GCMKW}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown key encryption algorithm: " + alg);
}

JWA::ContentEncryptionAlgorithm JWA::contentEncryptionAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, ContentEncryptionAlgorithm> algMap = {
        {"A128CBC-HS256", ContentEncryptionAlgorithm::A128CBC_HS256},
        {"A192CBC-HS384", ContentEncryptionAlgorithm::A192CBC_HS384},
        {"A256CBC-HS512", ContentEncryptionAlgorithm::A256CBC_HS512},
        {"A128GCM", ContentEncryptionAlgorithm::A128GCM},
        {"A192GCM", ContentEncryptionAlgorithm::A192GCM},
        {"A256GCM", ContentEncryptionAlgorithm::A256GCM}
    };
    
    auto it = algMap.find(alg);
    if (it != algMap.end())
    {
        return it->second;
    }
    
    throw std::runtime_error("Unknown content encryption algorithm: " + alg);
}

} // namespace jose
} // namespace Vlinder
