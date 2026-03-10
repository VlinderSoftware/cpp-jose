#include <openssl/params.h>

#include <cstring>
#include <map>
#include <stdexcept>

#include "back_end.hpp"
#include "back_end_factory.hpp"
#include "endian.hpp"
#include "jwa.hpp"
#include "jwk.hpp"

using namespace std;

#if defined(JOSE_USE_OPENSSL)

namespace Vlinder {
namespace JOSE {

namespace {

// Perform ECDH key agreement
vector<unsigned char> performECDH(Details::KeyRing const &private_key,
                                  Details::KeyRing const &public_key)
{
    Details::Backend &backend(private_key.getBackend());
    return backend.derive(private_key, public_key);
}

vector<unsigned char> hmacSign(void const *md, const JWK &key, vector<unsigned char> const &data)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    size_t key_len = 0;
    unsigned char *key_data = nullptr;

    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &key_len) != 1)
    {
        throw runtime_error("Failed to get key length: " + getOpenSSLError());
    }

    key_data = new unsigned char[key_len];
    if (EVP_PKEY_get_raw_private_key(pkey, key_data, &key_len) != 1)
    {
        delete[] key_data;
        throw runtime_error("Failed to get key data: " + getOpenSSLError());
    }

    unsigned int sig_len;
    vector<unsigned char> signature(EVP_MD_size(static_cast<const EVP_MD *>(md)));

    if (!HMAC(static_cast<const EVP_MD *>(md),
              key_data,
              key_len,
              data.data(),
              data.size(),
              signature.data(),
              &sig_len))
    {
        delete[] key_data;
        throw runtime_error("HMAC signing failed: " + getOpenSSLError());
    }

    delete[] key_data;
    signature.resize(sig_len);
    return signature;
}

bool hmacVerify(void const *md,
                const JWK &key,
                vector<unsigned char> const &data,
                vector<unsigned char> const &signature)
{
    vector<unsigned char> expected_sig = hmacSign(md, key, data);

    if (expected_sig.size() != signature.size())
    {
        return false;
    }

    return CRYPTO_memcmp(expected_sig.data(), signature.data(), signature.size()) == 0;
}
vector<unsigned char>
rsaSign(void const *md, const JWK &key, vector<unsigned char> const &data, bool use_pss)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    EVP_PKEY_CTX *pctx = nullptr;

    if (EVP_DigestSignInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to initialize signing: " + getOpenSSLError());
    }

    if (use_pss)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to set PSS padding: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to set PSS salt length: " + getOpenSSLError());
        }
    }

    size_t sig_len;
    if (EVP_DigestSign(mdctx, nullptr, &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(mdctx, signature.data(), &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    signature.resize(sig_len);
    return signature;
}

bool rsaVerify(void const *md,
               const JWK &key,
               vector<unsigned char> const &data,
               vector<unsigned char> const &signature,
               bool use_pss)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    EVP_PKEY_CTX *pctx = nullptr;

    if (EVP_DigestVerifyInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to initialize verification: " + getOpenSSLError());
    }

    if (use_pss)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to set PSS padding: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0)
        {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Failed to set PSS salt length: " + getOpenSSLError());
        }
    }

    int result =
        EVP_DigestVerify(mdctx, signature.data(), signature.size(), data.data(), data.size());

    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

vector<unsigned char> ecdsaSign(void const *md, const JWK &key, vector<unsigned char> const &data)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        throw runtime_error("Failed to create MD context: " + getOpenSSLError());
    }

    EVP_PKEY_CTX *pctx = nullptr;
    if (EVP_DigestSignInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to initialize signing: " + getOpenSSLError());
    }

    // Prefer OpenSSL 3 provider format control when available: produce IEEE P1363
    // signatures directly (r || s), which is exactly the JWS ECDSA encoding.
    bool use_p1363 = false;
    if (pctx != nullptr)
    {
        char sig_format[] = "ieee-p1363";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("ecdsa_sig_format", sig_format, sizeof(sig_format)),
            OSSL_PARAM_construct_end()};
        use_p1363 = (EVP_PKEY_CTX_set_params(pctx, params) == 1);
    }

    size_t sig_len;
    if (EVP_DigestSign(mdctx, nullptr, &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Failed to get signature length: " + getOpenSSLError());
    }

    vector<unsigned char> signature(sig_len);
    if (EVP_DigestSign(mdctx, signature.data(), &sig_len, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("Signing failed: " + getOpenSSLError());
    }

    EVP_MD_CTX_free(mdctx);
    signature.resize(sig_len);

    if (use_p1363)
    {
        return signature;
    }

    unsigned char const *p = signature.data();
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(nullptr, &p, signature.size());
    if (!ecdsa_sig)
    {
        throw runtime_error("Failed to parse ECDSA signature: " + getOpenSSLError());
    }

    const BIGNUM *r;
    const BIGNUM *s;
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
        if (EVP_PKEY_get_utf8_string_param(pkey,
                                           OSSL_PKEY_PARAM_GROUP_NAME,
                                           curve_name,
                                           sizeof(curve_name),
                                           &curve_name_len))
        {
            string group_name(curve_name);
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
        throw runtime_error("Unable to determine EC curve size");
    }

    vector<unsigned char> signature(2 * key_size, 0);

    BN_bn2binpad(r, signature.data(), key_size);
    BN_bn2binpad(s, signature.data() + key_size, key_size);

    ECDSA_SIG_free(ecdsa_sig);
    return signature;
}

bool ecdsaVerify(void const *md,
                 const JWK &key,
                 vector<unsigned char> const &data,
                 vector<unsigned char> const &signature)
{
    if (signature.size() % 2 != 0)
    {
        return false;
    }

    size_t key_size = signature.size() / 2;

    BIGNUM *r = BN_bin2bn(signature.data(), key_size, nullptr);
    BIGNUM *s = BN_bin2bn(signature.data() + key_size, key_size, nullptr);

    if (!r || !s)
    {
        if (r)
            BN_free(r);
        if (s)
            BN_free(s);
        return false;
    }

    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig)
    {
        BN_free(r);
        BN_free(s);
        return false;
    }

    ECDSA_SIG_set0(ecdsa_sig, r, s);

    unsigned char *der_sig = nullptr;
    int der_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);

    if (der_len <= 0)
    {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    vector<unsigned char> der_signature(der_sig, der_sig + der_len);
    OPENSSL_free(der_sig);
    ECDSA_SIG_free(ecdsa_sig);

    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        return false;
    }

    EVP_PKEY_CTX *pctx = nullptr;
    if (EVP_DigestVerifyInit(mdctx, &pctx, md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (pctx != nullptr)
    {
        char sig_format[] = "ieee-p1363";
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("ecdsa_sig_format", sig_format, sizeof(sig_format)),
            OSSL_PARAM_construct_end()};

        if (EVP_PKEY_CTX_set_params(pctx, params) == 1)
        {
            int const result = EVP_DigestVerify(mdctx,
                                                signature.data(),
                                                signature.size(),
                                                data.data(),
                                                data.size());
            EVP_MD_CTX_free(mdctx);
            return result == 1;
        }
    }

    int result = EVP_DigestVerify(mdctx,
                                  der_signature.data(),
                                  der_signature.size(),
                                  data.data(),
                                  data.size());

    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

vector<unsigned char> rsaEncrypt(const JWK &key,
                                 vector<unsigned char> const &plaintext,
                                 int padding,
                                 const EVP_MD *md = nullptr)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
    {
        throw runtime_error("Failed to create context: " + getOpenSSLError());
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to set padding: " + getOpenSSLError());
    }

    if (padding == RSA_PKCS1_OAEP_PADDING && md)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to set OAEP MD: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to set MGF1 MD: " + getOpenSSLError());
        }
    }

    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, nullptr, &out_len, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    vector<unsigned char> ciphertext(out_len);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Encryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    ciphertext.resize(out_len);
    return ciphertext;
}

vector<unsigned char> rsaDecrypt(const JWK &key,
                                 vector<unsigned char> const &ciphertext,
                                 int padding,
                                 const EVP_MD *md = nullptr)
{
    EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
    if (!pkey)
    {
        throw runtime_error("Invalid key");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
    {
        throw runtime_error("Failed to create context: " + getOpenSSLError());
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to set padding: " + getOpenSSLError());
    }

    if (padding == RSA_PKCS1_OAEP_PADDING && md)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to set OAEP MD: " + getOpenSSLError());
        }

        if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            throw runtime_error("Failed to set MGF1 MD: " + getOpenSSLError());
        }
    }

    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, nullptr, &out_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to get output length: " + getOpenSSLError());
    }

    vector<unsigned char> plaintext(out_len);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) <=
        0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Decryption failed: " + getOpenSSLError());
    }

    EVP_PKEY_CTX_free(ctx);
    plaintext.resize(out_len);
    return plaintext;
}

vector<unsigned char> aesKeyWrap(vector<unsigned char> const &kek,
                                 vector<unsigned char> const &plaintext)
{
    // Use EVP API for OpenSSL 3.0+
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER *cipher = nullptr;
    if (kek.size() == 16)
        cipher = EVP_aes_128_wrap();
    else if (kek.size() == 24)
        cipher = EVP_aes_192_wrap();
    else if (kek.size() == 32)
        cipher = EVP_aes_256_wrap();
    else
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Invalid AES key size for key wrap");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, kek.data(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize AES key wrap: " + getOpenSSLError());
    }

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int out_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size()) !=
        1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES key wrap failed: " + getOpenSSLError());
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES key wrap finalization failed: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(out_len + final_len);
    return ciphertext;
}

vector<unsigned char> aesKeyUnwrap(vector<unsigned char> const &kek,
                                   vector<unsigned char> const &ciphertext)
{
    // Use EVP API for OpenSSL 3.0+
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER *cipher = nullptr;
    if (kek.size() == 16)
        cipher = EVP_aes_128_wrap();
    else if (kek.size() == 24)
        cipher = EVP_aes_192_wrap();
    else if (kek.size() == 32)
        cipher = EVP_aes_256_wrap();
    else
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Invalid AES key size for key unwrap");
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, kek.data(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize AES key unwrap: " + getOpenSSLError());
    }

    vector<unsigned char> plaintext(ciphertext.size());
    int out_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), ciphertext.size()) !=
        1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES key unwrap failed: " + getOpenSSLError());
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES key unwrap finalization failed: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len + final_len);
    return plaintext;
}

vector<unsigned char> aesGcmKeyWrap(vector<unsigned char> const &kek,
                                    vector<unsigned char> const &plaintext,
                                    vector<unsigned char> &iv,
                                    vector<unsigned char> &tag)
{
    if (iv.empty())
    {
        iv.resize(12);
        if (RAND_bytes(iv.data(), iv.size()) != 1)
        {
            throw runtime_error("Failed to generate IV: " + getOpenSSLError());
        }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER *cipher = nullptr;
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
            throw runtime_error("Invalid key size for AES-GCM");
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, kek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    vector<unsigned char> ciphertext(plaintext.size());
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

vector<unsigned char> aesGcmKeyUnwrap(vector<unsigned char> const &kek,
                                      vector<unsigned char> const &ciphertext,
                                      vector<unsigned char> const &iv,
                                      vector<unsigned char> const &tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    const EVP_CIPHER *cipher = nullptr;
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
            throw runtime_error("Invalid key size for AES-GCM");
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, kek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    vector<unsigned char> plaintext(ciphertext.size());
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            tag.size(),
                            const_cast<unsigned char *>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption finalization failed (authentication failed): " +
                            getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

pair<vector<unsigned char>, vector<unsigned char>>
aesCbcHmacEncrypt(const EVP_CIPHER *cipher,
                  const EVP_MD *md,
                  vector<unsigned char> const &cek,
                  vector<unsigned char> const &iv,
                  vector<unsigned char> const &plaintext,
                  vector<unsigned char> const &aad)
{
    size_t key_len = cek.size() / 2;
    vector<unsigned char> mac_key(cek.begin(), cek.begin() + key_len);
    vector<unsigned char> enc_key(cek.begin() + key_len, cek.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, enc_key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(cipher));
    int len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aad_bits & 0xFF;
        aad_bits >>= 8;
    }

    vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    unsigned int mac_len;
    vector<unsigned char> mac(EVP_MD_size(md));

    if (!HMAC(md,
              mac_key.data(),
              mac_key.size(),
              mac_data.data(),
              mac_data.size(),
              mac.data(),
              &mac_len))
    {
        throw runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    vector<unsigned char> tag(mac.begin(), mac.begin() + key_len);

    return {ciphertext, tag};
}

vector<unsigned char> aesCbcHmacDecrypt(const EVP_CIPHER *cipher,
                                        const EVP_MD *md,
                                        vector<unsigned char> const &cek,
                                        vector<unsigned char> const &iv,
                                        vector<unsigned char> const &ciphertext,
                                        vector<unsigned char> const &aad,
                                        vector<unsigned char> const &tag)
{
    size_t key_len = cek.size() / 2;
    vector<unsigned char> mac_key(cek.begin(), cek.begin() + key_len);
    vector<unsigned char> enc_key(cek.begin() + key_len, cek.end());

    vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int i = 7; i >= 0; --i)
    {
        al[i] = aad_bits & 0xFF;
        aad_bits >>= 8;
    }

    vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    unsigned int mac_len;
    vector<unsigned char> mac(EVP_MD_size(md));

    if (!HMAC(md,
              mac_key.data(),
              mac_key.size(),
              mac_data.data(),
              mac_data.size(),
              mac.data(),
              &mac_len))
    {
        throw runtime_error("HMAC computation failed: " + getOpenSSLError());
    }

    vector<unsigned char> expected_tag(mac.begin(), mac.begin() + key_len);

    if (expected_tag.size() != tag.size() ||
        CRYPTO_memcmp(expected_tag.data(), tag.data(), tag.size()) != 0)
    {
        throw runtime_error("Authentication tag verification failed");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, enc_key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption finalization failed: " + getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

pair<vector<unsigned char>, vector<unsigned char>>
aesGcmEncrypt(const EVP_CIPHER *cipher,
              vector<unsigned char> const &cek,
              vector<unsigned char> const &iv,
              vector<unsigned char> const &plaintext,
              vector<unsigned char> const &aad)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption: " + getOpenSSLError());
    }

    int len;

    if (!aad.empty())
    {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to process AAD: " + getOpenSSLError());
        }
    }

    vector<unsigned char> ciphertext(plaintext.size());

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed: " + getOpenSSLError());
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption finalization failed: " + getOpenSSLError());
    }

    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to get tag: " + getOpenSSLError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return {ciphertext, tag};
}

vector<unsigned char> aesGcmDecrypt(const EVP_CIPHER *cipher,
                                    vector<unsigned char> const &cek,
                                    vector<unsigned char> const &iv,
                                    vector<unsigned char> const &ciphertext,
                                    vector<unsigned char> const &aad,
                                    vector<unsigned char> const &tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLError());
    }

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption: " + getOpenSSLError());
    }

    int len;

    if (!aad.empty())
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Failed to process AAD: " + getOpenSSLError());
        }
    }

    vector<unsigned char> plaintext(ciphertext.size());

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed: " + getOpenSSLError());
    }

    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            tag.size(),
                            const_cast<unsigned char *>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to set tag: " + getOpenSSLError());
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption finalization failed (authentication failed): " +
                            getOpenSSLError());
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

}  // namespace

vector<unsigned char>
JWA::sign(SignatureAlgorithm algorithm, JWK const &key, vector<unsigned char> const &data)
{
    auto const &backend = getBackend();
    void const *hash_alg = backend.getHashAlgorithm(algorithm);
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            return hmacSign(hash_alg, key, data);
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
            return rsaSign(hash_alg, key, data, false);
        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::es512:
            return ecdsaSign(hash_alg, key, data);
        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            return rsaSign(hash_alg, key, data, true);
        case SignatureAlgorithm::none:
            return vector<unsigned char>();
        default:
            throw runtime_error("Unsupported signature algorithm");
    }
}

bool JWA::verify(SignatureAlgorithm algorithm,
                 JWK const &key,
                 vector<unsigned char> const &data,
                 vector<unsigned char> const &signature)
{
    if (algorithm == SignatureAlgorithm::none)
    {
        return signature.empty();
    }
    auto const &backend = getBackend();
    void const *hash_alg = backend.getHashAlgorithm(algorithm);
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            return hmacVerify(hash_alg, key, data, signature);
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
            return rsaVerify(hash_alg, key, data, signature, false);
        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::es512:
            return ecdsaVerify(hash_alg, key, data, signature);
        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            return rsaVerify(hash_alg, key, data, signature, true);
        default:
            throw runtime_error("Unsupported signature algorithm");
    }
}

vector<unsigned char> JWA::encryptKey(KeyEncryptionAlgorithm algorithm,
                                      const JWK &key,
                                      vector<unsigned char> const &cek,
                                      vector<unsigned char> *out_iv,
                                      vector<unsigned char> *out_tag,
                                      JWK *ephemeral_key,
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
            EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
            if (!pkey)
            {
                throw runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char *kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw runtime_error("Failed to get key data");
            }

            vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            return aesKeyWrap(kek, cek);
        }

        case KeyEncryptionAlgorithm::dir:
            return cek;

        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
        {
            EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
            if (!pkey)
            {
                throw runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char *kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw runtime_error("Failed to get key data");
            }

            vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            vector<unsigned char> iv;
            vector<unsigned char> tag;
            vector<unsigned char> result = aesGcmKeyWrap(kek, cek, iv, tag);

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

            EVP_PKEY *recipient_key = static_cast<EVP_PKEY *>(key.getKey());
            if (!recipient_key)
            {
                throw runtime_error("Invalid recipient key");
            }

            // Get the curve name from recipient's key
            string curve_name = getECCurveName(recipient_key);

            // Generate ephemeral EC key pair on the same curve
            // Use signature as the use parameter (ephemeral keys for ECDH don't use the 'use'
            // field)
            JWK epk = JWK::generateEC(JWK::Use::signature, curve_name);
            EVP_PKEY *ephemeral_private_key = static_cast<EVP_PKEY *>(epk.getKey());

            // Perform ECDH to get shared secret
            vector<unsigned char> shared_secret = performECDH(ephemeral_private_key, recipient_key);

            // Determine key length needed based on content encryption algorithm
            size_t key_len = cek.size();  // Use the provided CEK size
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
            string algorithm = toString(content_alg);
            vector<unsigned char> derived_cek =
                back_end->concatKDF(shared_secret, key_len, algorithm);

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
            throw runtime_error("Unsupported key encryption algorithm");
    }
}

vector<unsigned char> JWA::decryptKey(KeyEncryptionAlgorithm algorithm,
                                      const JWK &key,
                                      vector<unsigned char> const &encrypted_cek,
                                      vector<unsigned char> const *in_iv,
                                      vector<unsigned char> const *in_tag,
                                      const JWK *ephemeral_key,
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
            EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
            if (!pkey)
            {
                throw runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char *kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw runtime_error("Failed to get key data");
            }

            vector<unsigned char> kek(kek_data, kek_data + kek_len);
            delete[] kek_data;

            return aesKeyUnwrap(kek, encrypted_cek);
        }

        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
        {
            if (!in_iv || !in_tag)
            {
                throw runtime_error("IV and tag required for AES-GCM key unwrap");
            }

            EVP_PKEY *pkey = static_cast<EVP_PKEY *>(key.getKey());
            if (!pkey)
            {
                throw runtime_error("Invalid key");
            }

            size_t kek_len = 0;
            unsigned char *kek_data = nullptr;

            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &kek_len) != 1)
            {
                throw runtime_error("Failed to get key length");
            }

            kek_data = new unsigned char[kek_len];
            if (EVP_PKEY_get_raw_private_key(pkey, kek_data, &kek_len) != 1)
            {
                delete[] kek_data;
                throw runtime_error("Failed to get key data");
            }

            vector<unsigned char> kek(kek_data, kek_data + kek_len);
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
                throw runtime_error("Ephemeral key required for ECDH-ES");
            }

            EVP_PKEY *recipient_private_key = static_cast<EVP_PKEY *>(key.getKey());
            if (!recipient_private_key)
            {
                throw runtime_error("Invalid recipient key");
            }

            EVP_PKEY *ephemeral_public_key = static_cast<EVP_PKEY *>(ephemeral_key->getKey());
            if (!ephemeral_public_key)
            {
                throw runtime_error("Invalid ephemeral key");
            }

            // Perform ECDH to get shared secret
            vector<unsigned char> shared_secret =
                performECDH(recipient_private_key, ephemeral_public_key);

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
            string algorithm = toString(content_alg);
            vector<unsigned char> derived_cek = concatKDF(shared_secret, key_len, algorithm);

            return derived_cek;
        }

        default:
            throw runtime_error("Unsupported key encryption algorithm");
    }
}

pair<vector<unsigned char>, vector<unsigned char>>
JWA::encryptContent(ContentEncryptionAlgorithm algorithm,
                    vector<unsigned char> const &cek,
                    vector<unsigned char> const &iv,
                    vector<unsigned char> const &plaintext,
                    vector<unsigned char> const &aad)
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
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

vector<unsigned char> JWA::decryptContent(ContentEncryptionAlgorithm algorithm,
                                          vector<unsigned char> const &cek,
                                          vector<unsigned char> const &iv,
                                          vector<unsigned char> const &ciphertext,
                                          vector<unsigned char> const &aad,
                                          vector<unsigned char> const &tag)
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacDecrypt(EVP_aes_128_cbc(),
                                     EVP_sha256(),
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);

        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacDecrypt(EVP_aes_192_cbc(),
                                     EVP_sha384(),
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);

        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacDecrypt(EVP_aes_256_cbc(),
                                     EVP_sha512(),
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);

        case ContentEncryptionAlgorithm::a128gcm:
            return aesGcmDecrypt(EVP_aes_128_gcm(), cek, iv, ciphertext, aad, tag);

        case ContentEncryptionAlgorithm::a192gcm:
            return aesGcmDecrypt(EVP_aes_192_gcm(), cek, iv, ciphertext, aad, tag);

        case ContentEncryptionAlgorithm::a256gcm:
            return aesGcmDecrypt(EVP_aes_256_gcm(), cek, iv, ciphertext, aad, tag);

        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

}  // namespace JOSE
}  // namespace Vlinder

#endif
