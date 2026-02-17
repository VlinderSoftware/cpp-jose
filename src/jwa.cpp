#include "jose/jwa.hpp"

#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <cstring>
#include <map>
#include <stdexcept>

#include "jose/jwk.hpp"

namespace Vlinder {
namespace JOSE {

namespace {

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
        case JWA::SignatureAlgorithm::hs256:
        case JWA::SignatureAlgorithm::rs256:
        case JWA::SignatureAlgorithm::es256:
        case JWA::SignatureAlgorithm::ps256:
            return EVP_sha256();
        case JWA::SignatureAlgorithm::hs384:
        case JWA::SignatureAlgorithm::rs384:
        case JWA::SignatureAlgorithm::es384:
        case JWA::SignatureAlgorithm::ps384:
            return EVP_sha384();
        case JWA::SignatureAlgorithm::hs512:
        case JWA::SignatureAlgorithm::rs512:
        case JWA::SignatureAlgorithm::es512:
        case JWA::SignatureAlgorithm::ps512:
            return EVP_sha512();
        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

// Concat KDF implementation per RFC 7518 Section 4.6.2
std::vector<unsigned char> concatKDF(const std::vector<unsigned char>& shared_secret,
                                      size_t key_data_len,
                                      const std::string& algorithm,
                                      const std::vector<unsigned char>& apu = {},
                                      const std::vector<unsigned char>& apv = {})
{
    // OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || KeyDataLen
    std::vector<unsigned char> other_info;
    
    // AlgorithmID - length prefixed algorithm string
    uint32_t alg_len = htonl(algorithm.length());
    other_info.insert(other_info.end(), 
                     reinterpret_cast<const unsigned char*>(&alg_len), 
                     reinterpret_cast<const unsigned char*>(&alg_len) + 4);
    other_info.insert(other_info.end(), algorithm.begin(), algorithm.end());
    
    // PartyUInfo (APU) - length prefixed
    uint32_t apu_len = htonl(apu.size());
    other_info.insert(other_info.end(), 
                     reinterpret_cast<const unsigned char*>(&apu_len), 
                     reinterpret_cast<const unsigned char*>(&apu_len) + 4);
    if (!apu.empty())
    {
        other_info.insert(other_info.end(), apu.begin(), apu.end());
    }
    
    // PartyVInfo (APV) - length prefixed
    uint32_t apv_len = htonl(apv.size());
    other_info.insert(other_info.end(), 
                     reinterpret_cast<const unsigned char*>(&apv_len), 
                     reinterpret_cast<const unsigned char*>(&apv_len) + 4);
    if (!apv.empty())
    {
        other_info.insert(other_info.end(), apv.begin(), apv.end());
    }
    
    // KeyDataLen in bits (big-endian)
    uint32_t key_data_len_bits = htonl(key_data_len * 8);
    other_info.insert(other_info.end(), 
                     reinterpret_cast<const unsigned char*>(&key_data_len_bits), 
                     reinterpret_cast<const unsigned char*>(&key_data_len_bits) + 4);
    
    // Perform Concat KDF with SHA-256
    std::vector<unsigned char> derived_key;
    uint32_t reps = (key_data_len + 31) / 32; // ceil(key_data_len / hash_len), SHA-256 = 32 bytes
    
    for (uint32_t i = 1; i <= reps; ++i)
    {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            throw std::runtime_error("Failed to create digest context");
        }
        
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize digest");
        }
        
        // Hash round number (big-endian)
        uint32_t round = htonl(i);
        if (EVP_DigestUpdate(ctx, &round, 4) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update digest");
        }
        
        // Hash shared secret
        if (EVP_DigestUpdate(ctx, shared_secret.data(), shared_secret.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update digest");
        }
        
        // Hash OtherInfo
        if (EVP_DigestUpdate(ctx, other_info.data(), other_info.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update digest");
        }
        
        unsigned char hash[32];
        unsigned int hash_len;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize digest");
        }
        
        derived_key.insert(derived_key.end(), hash, hash + hash_len);
        EVP_MD_CTX_free(ctx);
    }
    
    derived_key.resize(key_data_len);
    return derived_key;
}

// Perform ECDH key agreement
std::vector<unsigned char> performECDH(EVP_PKEY* private_key, EVP_PKEY* public_key)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx)
    {
        throw std::runtime_error("Failed to create PKEY context");
    }
    
    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key derivation");
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, public_key) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set peer key");
    }
    
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine shared secret length");
    }
    
    std::vector<unsigned char> shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to derive shared secret");
    }
    
    EVP_PKEY_CTX_free(ctx);
    shared_secret.resize(secret_len);
    return shared_secret;
}

// Get EC curve name from EVP_PKEY
std::string getECCurveName(EVP_PKEY* pkey)
{
    char curve_name[256] = {0};
    size_t curve_name_len = sizeof(curve_name);
    
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, 
                                       curve_name, sizeof(curve_name), &curve_name_len) != 1)
    {
        throw std::runtime_error("Failed to get EC curve name");
    }
    
    std::string openssl_name(curve_name);
    
    // Convert OpenSSL curve names to JWA curve names
    if (openssl_name == "prime256v1")
    {
        return "P-256";
    }
    else if (openssl_name == "secp384r1")
    {
        return "P-384";
    }
    else if (openssl_name == "secp521r1")
    {
        return "P-521";
    }
    else
    {
        // Return as-is if we don't recognize it
        return openssl_name;
    }
}

std::vector<unsigned char> hmacSign(const EVP_MD* md, const JWK& key,
                                    const std::vector<unsigned char>& data)
{
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
    if (!pkey)
    {
        throw std::runtime_error("Invalid key");
    }

    size_t key_len = 0;
    unsigned char* key_data = nullptr;

    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &key_len) != 1)
    {
        throw std::runtime_error("Failed to get key length: " + getOpenSSLError());
    }

    key_data = new unsigned char[key_len];
    if (EVP_PKEY_get_raw_private_key(pkey, key_data, &key_len) != 1)
    {
        delete[] key_data;
        throw std::runtime_error("Failed to get key data: " + getOpenSSLError());
    }

    unsigned int sig_len;
    std::vector<unsigned char> signature(EVP_MD_size(md));

    if (!HMAC(md, key_data, key_len, data.data(), data.size(), signature.data(), &sig_len))
    {
        delete[] key_data;
        throw std::runtime_error("HMAC signing failed: " + getOpenSSLError());
    }

    delete[] key_data;
    signature.resize(sig_len);
    return signature;
}

bool hmacVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data,
                const std::vector<unsigned char>& signature)
{
    std::vector<unsigned char> expected_sig = hmacSign(md, key, data);

    if (expected_sig.size() != signature.size())
    {
        return false;
    }

    return CRYPTO_memcmp(expected_sig.data(), signature.data(), signature.size()) == 0;
}
std::vector<unsigned char> rsaSign(const EVP_MD* md, const JWK& key,
                                   const std::vector<unsigned char>& data, bool use_pss)
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

    if (use_pss)
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

    size_t sig_len;
    if (EVP_DigestSign(mdctx, nullptr, &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(mdctx, signature.data(), &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    signature.resize(sig_len);
    return signature;
}

bool rsaVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data,
               const std::vector<unsigned char>& signature, bool use_pss)
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

    if (use_pss)
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

    int result =
        EVP_DigestVerify(mdctx, signature.data(), signature.size(), data.data(), data.size());

    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

std::vector<unsigned char> ecdsaSign(const EVP_MD* md, const JWK& key,
                                     const std::vector<unsigned char>& data)
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

    size_t sig_len;
    if (EVP_DigestSign(mdctx, nullptr, &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    std::vector<unsigned char> der_signature(sig_len);
    if (EVP_DigestSign(mdctx, der_signature.data(), &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    der_signature.resize(sig_len);

    const unsigned char* p = der_signature.data();
    ECDSA_SIG* ecdsa_sig = d2i_ECDSA_SIG(nullptr, &p, der_signature.size());
    if (!ecdsa_sig)
    {
        throw std::runtime_error("Failed to parse ECDSA signature: " + getOpenSSLError());
    }

    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);

    // Get the field size from the EC key, not from the hash size
    size_t key_size = 0;
    int nid = 0;
    if (EVP_PKEY_get_int_param(pkey, "group", &nid) == 1)
    {
        // Determine key size based on curve
        if (nid == NID_X9_62_prime256v1)  // P-256
        {
            key_size = 32;
        }
        else if (nid == NID_secp384r1)  // P-384
        {
            key_size = 48;
        }
        else if (nid == NID_secp521r1)  // P-521
        {
            key_size = 66;  // ceil(521/8)
        }
    }
    
    if (key_size == 0)
    {
        // Fallback: try to get curve name as string
        char curve_name[80];
        size_t curve_name_len = sizeof(curve_name);
        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, 
                                           curve_name, sizeof(curve_name), &curve_name_len))
        {
            std::string group_name(curve_name);
            if (group_name == "prime256v1")
            {
                key_size = 32;
            }
            else if (group_name == "secp384r1")
            {
                key_size = 48;
            }
            else if (group_name == "secp521r1")
            {
                key_size = 66;
            }
        }
    }
    
    if (key_size == 0)
    {
        ECDSA_SIG_free(ecdsa_sig);
        throw std::runtime_error("Unable to determine EC curve size");
    }

    std::vector<unsigned char> signature(2 * key_size, 0);

    BN_bn2binpad(r, signature.data(), key_size);
    BN_bn2binpad(s, signature.data() + key_size, key_size);

    ECDSA_SIG_free(ecdsa_sig);
    return signature;
}

bool ecdsaVerify(const EVP_MD* md, const JWK& key, const std::vector<unsigned char>& data,
                 const std::vector<unsigned char>& signature)
{
    if (signature.size() % 2 != 0)
    {
        return false;
    }

    size_t key_size = signature.size() / 2;

    BIGNUM* r = BN_bin2bn(signature.data(), key_size, nullptr);
    BIGNUM* s = BN_bin2bn(signature.data() + key_size, key_size, nullptr);

    if (!r || !s)
    {
        if (r)
            BN_free(r);
        if (s)
            BN_free(s);
        return false;
    }

    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig)
    {
        BN_free(r);
        BN_free(s);
        return false;
    }

    ECDSA_SIG_set0(ecdsa_sig, r, s);

    unsigned char* der_sig = nullptr;
    int der_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);

    if (der_len <= 0)
    {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    std::vector<unsigned char> der_signature(der_sig, der_sig + der_len);
    OPENSSL_free(der_sig);
    ECDSA_SIG_free(ecdsa_sig);

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

    int result =
        EVP_DigestVerify(mdctx, der_signature.data(), der_signature.size(), data.data(), data.size());

    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

std::vector<unsigned char> rsaEncrypt(const JWK& key, const std::vector<unsigned char>& plaintext,
                                      int padding, const EVP_MD* md = nullptr)
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

    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(out_len);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    ciphertext.resize(out_len);
    return ciphertext;
}

std::vector<unsigned char> rsaDecrypt(const JWK& key, const std::vector<unsigned char>& ciphertext,
                                      int padding, const EVP_MD* md = nullptr)
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

    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(out_len);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    plaintext.resize(out_len);
    return plaintext;
}

std::vector<unsigned char> aesKeyWrap(const std::vector<unsigned char>& kek,
                                      const std::vector<unsigned char>& plaintext)
{
    // Use EVP API for OpenSSL 3.0+
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER* cipher = nullptr;
    if (kek.size() == 16)
        cipher = EVP_aes_128_wrap();
    else if (kek.size() == 24)
        cipher = EVP_aes_192_wrap();
    else if (kek.size() == 32)
        cipher = EVP_aes_256_wrap();
    else
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Invalid AES key size for key wrap");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, kek.data(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES key wrap: " + getOpenSSLError());
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int out_len = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES key wrap failed: " + getOpenSSLError());
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES key wrap finalization failed: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(out_len + final_len);
    return ciphertext;
}

std::vector<unsigned char> aesKeyUnwrap(const std::vector<unsigned char>& kek,
                                        const std::vector<unsigned char>& ciphertext)
{
    // Use EVP API for OpenSSL 3.0+
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER* cipher = nullptr;
    if (kek.size() == 16)
        cipher = EVP_aes_128_wrap();
    else if (kek.size() == 24)
        cipher = EVP_aes_192_wrap();
    else if (kek.size() == 32)
        cipher = EVP_aes_256_wrap();
    else
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Invalid AES key size for key unwrap");
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, kek.data(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES key unwrap: " + getOpenSSLError());
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int out_len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES key unwrap failed: " + getOpenSSLError());
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES key unwrap finalization failed: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len + final_len);
    return plaintext;
}

std::vector<unsigned char> aesGcmKeyWrap(const std::vector<unsigned char>& kek,
                                         const std::vector<unsigned char>& plaintext,
                                         std::vector<unsigned char>& iv,
                                         std::vector<unsigned char>& tag)
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
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 24:
            cipher = EVP_aes_192_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
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

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<unsigned char> aesGcmKeyUnwrap(const std::vector<unsigned char>& kek,
                                           const std::vector<unsigned char>& ciphertext,
                                           const std::vector<unsigned char>& iv,
                                           const std::vector<unsigned char>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER* cipher = nullptr;
    switch (kek.size())
    {
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 24:
            cipher = EVP_aes_192_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
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

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                            const_cast<unsigned char*>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed (authentication failed): " +
                                 getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
aesCbcHmacEncrypt(const EVP_CIPHER* cipher, const EVP_MD* md, const std::vector<unsigned char>& cek,
                  const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plaintext,
                  const std::vector<unsigned char>& aad)
{
    size_t key_len = cek.size() / 2;
    std::vector<unsigned char> mac_key(cek.begin(), cek.begin() + key_len);
    std::vector<unsigned char> enc_key(cek.begin() + key_len, cek.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, enc_key.data(), iv.data()) != 1)
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

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aad_bits & 0xFF;
        aad_bits >>= 8;
    }

    std::vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    unsigned int mac_len;
    std::vector<unsigned char> mac(EVP_MD_size(md));

    if (!HMAC(md, mac_key.data(), mac_key.size(), mac_data.data(), mac_data.size(), mac.data(),
              &mac_len))
    {
        throw std::runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    std::vector<unsigned char> tag(mac.begin(), mac.begin() + key_len);

    return {ciphertext, tag};
}

std::vector<unsigned char> aesCbcHmacDecrypt(const EVP_CIPHER* cipher, const EVP_MD* md,
                                             const std::vector<unsigned char>& cek,
                                             const std::vector<unsigned char>& iv,
                                             const std::vector<unsigned char>& ciphertext,
                                             const std::vector<unsigned char>& aad,
                                             const std::vector<unsigned char>& tag)
{
    size_t key_len = cek.size() / 2;
    std::vector<unsigned char> mac_key(cek.begin(), cek.begin() + key_len);
    std::vector<unsigned char> enc_key(cek.begin() + key_len, cek.end());

    std::vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aad_bits & 0xFF;
        aad_bits >>= 8;
    }

    std::vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    unsigned int mac_len;
    std::vector<unsigned char> mac(EVP_MD_size(md));

    if (!HMAC(md, mac_key.data(), mac_key.size(), mac_data.data(), mac_data.size(), mac.data(),
              &mac_len))
    {
        throw std::runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    std::vector<unsigned char> expected_tag(mac.begin(), mac.begin() + key_len);

    if (expected_tag.size() != tag.size() ||
        CRYPTO_memcmp(expected_tag.data(), tag.data(), tag.size()) != 0)
    {
        throw std::runtime_error("Authentication tag verification failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, enc_key.data(), iv.data()) != 1)
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

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed: " + getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
aesGcmEncrypt(const EVP_CIPHER* cipher, const std::vector<unsigned char>& cek,
              const std::vector<unsigned char>& iv, const std::vector<unsigned char>& plaintext,
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

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return {ciphertext, tag};
}

std::vector<unsigned char>
aesGcmDecrypt(const EVP_CIPHER* cipher, const std::vector<unsigned char>& cek,
              const std::vector<unsigned char>& iv, const std::vector<unsigned char>& ciphertext,
              const std::vector<unsigned char>& aad, const std::vector<unsigned char>& tag)
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

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                            const_cast<unsigned char*>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalization failed (authentication failed): " +
                                 getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

}  // namespace

std::vector<unsigned char> JWA::sign(SignatureAlgorithm algorithm, const JWK& key,
                                     const std::vector<unsigned char>& data)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            return hmacSign(getMD(algorithm), key, data);

        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
            return rsaSign(getMD(algorithm), key, data, false);

        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::es512:
            return ecdsaSign(getMD(algorithm), key, data);

        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            return rsaSign(getMD(algorithm), key, data, true);

        case SignatureAlgorithm::none:
            return std::vector<unsigned char>();

        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

bool JWA::verify(SignatureAlgorithm algorithm, const JWK& key,
                 const std::vector<unsigned char>& data,
                 const std::vector<unsigned char>& signature)
{
    if (algorithm == SignatureAlgorithm::none)
    {
        return signature.empty();
    }

    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            return hmacVerify(getMD(algorithm), key, data, signature);

        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
            return rsaVerify(getMD(algorithm), key, data, signature, false);

        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::es512:
            return ecdsaVerify(getMD(algorithm), key, data, signature);

        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            return rsaVerify(getMD(algorithm), key, data, signature, true);

        default:
            throw std::runtime_error("Unsupported signature algorithm");
    }
}

std::vector<unsigned char> JWA::encryptKey(KeyEncryptionAlgorithm algorithm, const JWK& key,
                                           const std::vector<unsigned char>& cek,
                                           std::vector<unsigned char>* out_iv,
                                           std::vector<unsigned char>* out_tag,
                                           JWK* ephemeral_key,
                                           ContentEncryptionAlgorithm content_alg)
{
    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::rsa1_5:
            return rsaEncrypt(key, cek, RSA_PKCS1_PADDING);

        case KeyEncryptionAlgorithm::rsa_oaep:
            return rsaEncrypt(key, cek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());

        case KeyEncryptionAlgorithm::rsa_oaep_256:
            return rsaEncrypt(key, cek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());

        case KeyEncryptionAlgorithm::a128kw:
        case KeyEncryptionAlgorithm::a192kw:
        case KeyEncryptionAlgorithm::a256kw:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char* kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            return aesKeyWrap(kek, cek);
        }

        case KeyEncryptionAlgorithm::dir:
            return cek;

        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char* kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            std::vector<unsigned char> result = aesGcmKeyWrap(kek, cek, iv, tag);
            
            // Store IV and tag in output parameters if provided
            if (out_iv)
            {
                *out_iv = iv;
            }
            if (out_tag)
            {
                *out_tag = tag;
            }
            
            return result;
        }

        case KeyEncryptionAlgorithm::ecdh_es:
        {
            // ECDH-ES: Elliptic Curve Diffie-Hellman Ephemeral Static
            // For ECDH-ES, we derive the CEK directly (not encrypt it)
            
            EVP_PKEY* recipient_key = static_cast<EVP_PKEY*>(key.getKey());
            if (!recipient_key)
            {
                throw std::runtime_error("Invalid recipient key");
            }
            
            // Get the curve name from recipient's key
            std::string curve_name = getECCurveName(recipient_key);
            
            // Generate ephemeral EC key pair on the same curve
            // Use signature as the use parameter (ephemeral keys for ECDH don't use the 'use' field)
            JWK epk = JWK::generateEC(JWK::Use::signature, curve_name);
            EVP_PKEY* ephemeral_private_key = static_cast<EVP_PKEY*>(epk.getKey());
            
            // Perform ECDH to get shared secret
            std::vector<unsigned char> shared_secret = performECDH(ephemeral_private_key, recipient_key);
            
            // Determine key length needed based on content encryption algorithm
            size_t key_len = cek.size(); // Use the provided CEK size
            if (key_len == 0)
            {
                // If no CEK provided, determine size from content algorithm
                switch (content_alg)
                {
                    case ContentEncryptionAlgorithm::a128gcm:
                    case ContentEncryptionAlgorithm::a128cbc_hs256:
                        key_len = 16;
                        break;
                    case ContentEncryptionAlgorithm::a192gcm:
                    case ContentEncryptionAlgorithm::a192cbc_hs384:
                        key_len = 24;
                        break;
                    case ContentEncryptionAlgorithm::a256gcm:
                    case ContentEncryptionAlgorithm::a256cbc_hs512:
                        key_len = 32;
                        break;
                    default:
                        key_len = 32;
                }
            }
            
            // Use Concat KDF to derive the CEK
            std::string algorithm = toString(content_alg);
            std::vector<unsigned char> derived_cek = concatKDF(shared_secret, key_len, algorithm);
            
            // Store the ephemeral public key for inclusion in JWE header
            if (ephemeral_key)
            {
                *ephemeral_key = epk;
            }
            
            // For ECDH-ES, return the derived CEK (which caller will use as the CEK)
            // The "encrypted key" field in JWE will be empty
            return derived_cek;
        }

        default:
            throw std::runtime_error("Unsupported key encryption algorithm");
    }
}

std::vector<unsigned char> JWA::decryptKey(KeyEncryptionAlgorithm algorithm, const JWK& key,
                                           const std::vector<unsigned char>& encrypted_cek,
                                           const std::vector<unsigned char>* in_iv,
                                           const std::vector<unsigned char>* in_tag,
                                           const JWK* ephemeral_key,
                                           ContentEncryptionAlgorithm content_alg)
{
    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::rsa1_5:
            return rsaDecrypt(key, encrypted_cek, RSA_PKCS1_PADDING);

        case KeyEncryptionAlgorithm::rsa_oaep:
            return rsaDecrypt(key, encrypted_cek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());

        case KeyEncryptionAlgorithm::rsa_oaep_256:
            return rsaDecrypt(key, encrypted_cek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());

        case KeyEncryptionAlgorithm::a128kw:
        case KeyEncryptionAlgorithm::a192kw:
        case KeyEncryptionAlgorithm::a256kw:
        {
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char* kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            return aesKeyUnwrap(kek, encrypted_cek);
        }

        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
        {
            if (!in_iv || !in_tag)
            {
                throw std::runtime_error("IV and tag required for AES-GCM key unwrap");
            }
            
            EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.getKey());
            if (!pkey)
            {
                throw std::runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char* kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw std::runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw std::runtime_error("Failed to get key data");
            }

            std::vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            return aesGcmKeyUnwrap(kek, encrypted_cek, *in_iv, *in_tag);
        }

        case KeyEncryptionAlgorithm::dir:
            return encrypted_cek;

        case KeyEncryptionAlgorithm::ecdh_es:
        {
            // ECDH-ES decryption: derive CEK from ephemeral public key and recipient's private key
            if (!ephemeral_key)
            {
                throw std::runtime_error("Ephemeral key required for ECDH-ES");
            }
            
            EVP_PKEY* recipient_private_key = static_cast<EVP_PKEY*>(key.getKey());
            if (!recipient_private_key)
            {
                throw std::runtime_error("Invalid recipient key");
            }
            
            EVP_PKEY* ephemeral_public_key = static_cast<EVP_PKEY*>(ephemeral_key->getKey());
            if (!ephemeral_public_key)
            {
                throw std::runtime_error("Invalid ephemeral key");
            }
            
            // Perform ECDH to get shared secret
            std::vector<unsigned char> shared_secret = performECDH(recipient_private_key, ephemeral_public_key);
            
            // Determine key length from content encryption algorithm
            size_t key_len;
            switch (content_alg)
            {
                case ContentEncryptionAlgorithm::a128gcm:
                case ContentEncryptionAlgorithm::a128cbc_hs256:
                    key_len = 16;
                    break;
                case ContentEncryptionAlgorithm::a192gcm:
                case ContentEncryptionAlgorithm::a192cbc_hs384:
                    key_len = 24;
                    break;
                case ContentEncryptionAlgorithm::a256gcm:
                case ContentEncryptionAlgorithm::a256cbc_hs512:
                    key_len = 32;
                    break;
                default:
                    key_len = 32;
            }
            
            // Use Concat KDF to derive the CEK
            std::string algorithm = toString(content_alg);
            std::vector<unsigned char> derived_cek = concatKDF(shared_secret, key_len, algorithm);
            
            return derived_cek;
        }

        default:
            throw std::runtime_error("Unsupported key encryption algorithm");
    }
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
JWA::encryptContent(ContentEncryptionAlgorithm algorithm, const std::vector<unsigned char>& cek,
                    const std::vector<unsigned char>& iv,
                    const std::vector<unsigned char>& plaintext,
                    const std::vector<unsigned char>& aad)
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacEncrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, plaintext, aad);

        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacEncrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, plaintext, aad);

        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacEncrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, plaintext, aad);

        case ContentEncryptionAlgorithm::a128gcm:
            return aesGcmEncrypt(EVP_aes_128_gcm(), cek, iv, plaintext, aad);

        case ContentEncryptionAlgorithm::a192gcm:
            return aesGcmEncrypt(EVP_aes_192_gcm(), cek, iv, plaintext, aad);

        case ContentEncryptionAlgorithm::a256gcm:
            return aesGcmEncrypt(EVP_aes_256_gcm(), cek, iv, plaintext, aad);

        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

std::vector<unsigned char> JWA::decryptContent(ContentEncryptionAlgorithm algorithm,
                                               const std::vector<unsigned char>& cek,
                                               const std::vector<unsigned char>& iv,
                                               const std::vector<unsigned char>& ciphertext,
                                               const std::vector<unsigned char>& aad,
                                               const std::vector<unsigned char>& tag)
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacDecrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, ciphertext, aad,
                                     tag);

        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacDecrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, ciphertext, aad,
                                     tag);

        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacDecrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, ciphertext, aad,
                                     tag);

        case ContentEncryptionAlgorithm::a128gcm:
            return aesGcmDecrypt(EVP_aes_128_gcm(), cek, iv, ciphertext, aad, tag);

        case ContentEncryptionAlgorithm::a192gcm:
            return aesGcmDecrypt(EVP_aes_192_gcm(), cek, iv, ciphertext, aad, tag);

        case ContentEncryptionAlgorithm::a256gcm:
            return aesGcmDecrypt(EVP_aes_256_gcm(), cek, iv, ciphertext, aad, tag);

        default:
            throw std::runtime_error("Unsupported content encryption algorithm");
    }
}

std::string JWA::toString(SignatureAlgorithm alg)
{
    static const std::map<SignatureAlgorithm, std::string> alg_map = {
        {SignatureAlgorithm::hs256, "HS256"}, {SignatureAlgorithm::hs384, "HS384"},
        {SignatureAlgorithm::hs512, "HS512"}, {SignatureAlgorithm::rs256, "RS256"},
        {SignatureAlgorithm::rs384, "RS384"}, {SignatureAlgorithm::rs512, "RS512"},
        {SignatureAlgorithm::es256, "ES256"}, {SignatureAlgorithm::es384, "ES384"},
        {SignatureAlgorithm::es512, "ES512"}, {SignatureAlgorithm::ps256, "PS256"},
        {SignatureAlgorithm::ps384, "PS384"}, {SignatureAlgorithm::ps512, "PS512"},
        {SignatureAlgorithm::none, "none"}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown signature algorithm");
}

std::string JWA::toString(KeyEncryptionAlgorithm alg)
{
    static const std::map<KeyEncryptionAlgorithm, std::string> alg_map = {
        {KeyEncryptionAlgorithm::rsa1_5, "RSA1_5"},
        {KeyEncryptionAlgorithm::rsa_oaep, "RSA-OAEP"},
        {KeyEncryptionAlgorithm::rsa_oaep_256, "RSA-OAEP-256"},
        {KeyEncryptionAlgorithm::a128kw, "A128KW"},
        {KeyEncryptionAlgorithm::a192kw, "A192KW"},
        {KeyEncryptionAlgorithm::a256kw, "A256KW"},
        {KeyEncryptionAlgorithm::dir, "dir"},
        {KeyEncryptionAlgorithm::ecdh_es, "ECDH-ES"},
        {KeyEncryptionAlgorithm::a128gcmkw, "A128GCMKW"},
        {KeyEncryptionAlgorithm::a192gcmkw, "A192GCMKW"},
        {KeyEncryptionAlgorithm::a256gcmkw, "A256GCMKW"}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown key encryption algorithm");
}

std::string JWA::toString(ContentEncryptionAlgorithm alg)
{
    static const std::map<ContentEncryptionAlgorithm, std::string> alg_map = {
        {ContentEncryptionAlgorithm::a128cbc_hs256, "A128CBC-HS256"},
        {ContentEncryptionAlgorithm::a192cbc_hs384, "A192CBC-HS384"},
        {ContentEncryptionAlgorithm::a256cbc_hs512, "A256CBC-HS512"},
        {ContentEncryptionAlgorithm::a128gcm, "A128GCM"},
        {ContentEncryptionAlgorithm::a192gcm, "A192GCM"},
        {ContentEncryptionAlgorithm::a256gcm, "A256GCM"}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown content encryption algorithm");
}

JWA::SignatureAlgorithm JWA::signatureAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, SignatureAlgorithm> alg_map = {
        {"HS256", SignatureAlgorithm::hs256}, {"HS384", SignatureAlgorithm::hs384},
        {"HS512", SignatureAlgorithm::hs512}, {"RS256", SignatureAlgorithm::rs256},
        {"RS384", SignatureAlgorithm::rs384}, {"RS512", SignatureAlgorithm::rs512},
        {"ES256", SignatureAlgorithm::es256}, {"ES384", SignatureAlgorithm::es384},
        {"ES512", SignatureAlgorithm::es512}, {"PS256", SignatureAlgorithm::ps256},
        {"PS384", SignatureAlgorithm::ps384}, {"PS512", SignatureAlgorithm::ps512},
        {"none", SignatureAlgorithm::none}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown signature algorithm: " + alg);
}

JWA::KeyEncryptionAlgorithm JWA::keyEncryptionAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, KeyEncryptionAlgorithm> alg_map = {
        {"RSA1_5", KeyEncryptionAlgorithm::rsa1_5},
        {"RSA-OAEP", KeyEncryptionAlgorithm::rsa_oaep},
        {"RSA-OAEP-256", KeyEncryptionAlgorithm::rsa_oaep_256},
        {"A128KW", KeyEncryptionAlgorithm::a128kw},
        {"A192KW", KeyEncryptionAlgorithm::a192kw},
        {"A256KW", KeyEncryptionAlgorithm::a256kw},
        {"dir", KeyEncryptionAlgorithm::dir},
        {"ECDH-ES", KeyEncryptionAlgorithm::ecdh_es},
        {"A128GCMKW", KeyEncryptionAlgorithm::a128gcmkw},
        {"A192GCMKW", KeyEncryptionAlgorithm::a192gcmkw},
        {"A256GCMKW", KeyEncryptionAlgorithm::a256gcmkw}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown key encryption algorithm: " + alg);
}

JWA::ContentEncryptionAlgorithm JWA::contentEncryptionAlgorithmFromString(const std::string& alg)
{
    static const std::map<std::string, ContentEncryptionAlgorithm> alg_map = {
        {"A128CBC-HS256", ContentEncryptionAlgorithm::a128cbc_hs256},
        {"A192CBC-HS384", ContentEncryptionAlgorithm::a192cbc_hs384},
        {"A256CBC-HS512", ContentEncryptionAlgorithm::a256cbc_hs512},
        {"A128GCM", ContentEncryptionAlgorithm::a128gcm},
        {"A192GCM", ContentEncryptionAlgorithm::a192gcm},
        {"A256GCM", ContentEncryptionAlgorithm::a256gcm}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw std::runtime_error("Unknown content encryption algorithm: " + alg);
}

}  // namespace JOSE
}  // namespace Vlinder
