#include "cng_back_end.hpp"

#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <stdexcept>

using namespace std;

#ifndef JOSE_RSA_GENERATION_MAX_ATTEMPTS
#define JOSE_RSA_GENERATION_MAX_ATTEMPTS 8
#endif

static_assert(JOSE_RSA_GENERATION_MAX_ATTEMPTS > 0,
              "JOSE_RSA_GENERATION_MAX_ATTEMPTS must be greater than zero");

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace Vlinder {
namespace JOSE {
namespace Private {

namespace {

struct SignatureHashConfig
{
    HashAlgorithm hash_algorithm;
    wchar_t const *bcrypt_hash_name;
    ULONG hash_size;
};

SignatureHashConfig getSignatureHashConfig(SignatureAlgorithm algorithm)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::ps256:
            return {HashAlgorithm::sha256, BCRYPT_SHA256_ALGORITHM, 32};
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::ps384:
            return {HashAlgorithm::sha384, BCRYPT_SHA384_ALGORITHM, 48};
        case SignatureAlgorithm::hs512:
        case SignatureAlgorithm::rs512:
        case SignatureAlgorithm::es512:
        case SignatureAlgorithm::ps512:
            return {HashAlgorithm::sha512, BCRYPT_SHA512_ALGORITHM, 64};
        case SignatureAlgorithm::none:
            break;
    }

    throw runtime_error("Unsupported signature algorithm");
}

bool isRsaPkcs1Algorithm(SignatureAlgorithm algorithm)
{
    return algorithm == SignatureAlgorithm::rs256 || algorithm == SignatureAlgorithm::rs384 ||
           algorithm == SignatureAlgorithm::rs512;
}

bool isRsaPssAlgorithm(SignatureAlgorithm algorithm)
{
    return algorithm == SignatureAlgorithm::ps256 || algorithm == SignatureAlgorithm::ps384 ||
           algorithm == SignatureAlgorithm::ps512;
}

bool isEcAlgorithm(SignatureAlgorithm algorithm)
{
    return algorithm == SignatureAlgorithm::es256 || algorithm == SignatureAlgorithm::es384 ||
           algorithm == SignatureAlgorithm::es512;
}

vector<unsigned char> buildRsaFullPrivateBlob(RSAKey const &rsa_key)
{
    auto n(rsa_key.getN());
    auto e(rsa_key.getE());
    auto d(rsa_key.getD());
    auto p(rsa_key.getP());
    auto q(rsa_key.getQ());
    auto dp(rsa_key.getDp());
    auto dq(rsa_key.getDq());
    auto qi(rsa_key.getQi());

    if (n.empty() || e.empty() || d.empty() || p.empty() || q.empty() || dp.empty() || dq.empty() ||
        qi.empty())
    {
        throw runtime_error("RSA signing requires full private CRT parameters");
    }

    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    header.BitLength = static_cast<ULONG>(n.size() * 8);
    header.cbPublicExp = static_cast<ULONG>(e.size());
    header.cbModulus = static_cast<ULONG>(n.size());
    header.cbPrime1 = static_cast<ULONG>(p.size());
    header.cbPrime2 = static_cast<ULONG>(q.size());

    vector<unsigned char> blob(sizeof(BCRYPT_RSAKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), e.begin(), e.end());
    blob.insert(blob.end(), n.begin(), n.end());
    blob.insert(blob.end(), p.begin(), p.end());
    blob.insert(blob.end(), q.begin(), q.end());
    blob.insert(blob.end(), dp.begin(), dp.end());
    blob.insert(blob.end(), dq.begin(), dq.end());
    blob.insert(blob.end(), qi.begin(), qi.end());
    blob.insert(blob.end(), d.begin(), d.end());
    return blob;
}

vector<unsigned char> buildRsaPublicBlob(RSAKey const &rsa_key)
{
    auto n(rsa_key.getN());
    auto e(rsa_key.getE());
    if (n.empty() || e.empty())
    {
        throw runtime_error("RSA verification requires public key parameters n and e");
    }

    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = static_cast<ULONG>(n.size() * 8);
    header.cbPublicExp = static_cast<ULONG>(e.size());
    header.cbModulus = static_cast<ULONG>(n.size());
    header.cbPrime1 = 0;
    header.cbPrime2 = 0;

    vector<unsigned char> blob(sizeof(BCRYPT_RSAKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), e.begin(), e.end());
    blob.insert(blob.end(), n.begin(), n.end());
    return blob;
}

void resolveEcAlgorithm(SignatureAlgorithm algorithm,
                        wchar_t const *&alg_name,
                        ULONG &private_magic,
                        ULONG &public_magic)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::es256:
            alg_name = BCRYPT_ECDSA_P256_ALGORITHM;
            private_magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
            public_magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            return;
        case SignatureAlgorithm::es384:
            alg_name = BCRYPT_ECDSA_P384_ALGORITHM;
            private_magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
            public_magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
            return;
        case SignatureAlgorithm::es512:
            alg_name = BCRYPT_ECDSA_P521_ALGORITHM;
            private_magic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
            public_magic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
            return;
        default:
            break;
    }

    throw runtime_error("Unsupported ECDSA algorithm");
}

vector<unsigned char> buildEcPrivateBlob(ECKey const &ec_key, ULONG private_magic)
{
    auto x(ec_key.getX());
    auto y(ec_key.getY());
    auto d(ec_key.getD());

    if (x.empty() || y.empty() || d.empty())
    {
        throw runtime_error("ECDSA signing requires private EC key material");
    }
    if (x.size() != y.size() || x.size() != d.size())
    {
        throw runtime_error("EC key coordinates/scalar sizes are inconsistent");
    }

    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = private_magic;
    header.cbKey = static_cast<ULONG>(x.size());

    vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), x.begin(), x.end());
    blob.insert(blob.end(), y.begin(), y.end());
    blob.insert(blob.end(), d.begin(), d.end());
    return blob;
}

vector<unsigned char> buildEcPublicBlob(ECKey const &ec_key, ULONG public_magic)
{
    auto x(ec_key.getX());
    auto y(ec_key.getY());

    if (x.empty() || y.empty())
    {
        throw runtime_error("ECDSA verification requires EC public key material");
    }
    if (x.size() != y.size())
    {
        throw runtime_error("EC public key coordinates are inconsistent");
    }

    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = public_magic;
    header.cbKey = static_cast<ULONG>(x.size());

    vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), x.begin(), x.end());
    blob.insert(blob.end(), y.begin(), y.end());
    return blob;
}

vector<unsigned char> aesEncryptBlockEcb(vector<unsigned char> const &kek,
                                         vector<unsigned char> const &block)
{
    if (block.size() != 16)
    {
        throw runtime_error("AES block encryption requires a 16-byte block");
    }

    BCRYPT_ALG_HANDLE h_alg(nullptr);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + to_string(status));
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed: " + to_string(status));
    }

    ULONG key_object_size(0);
    ULONG result_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_size),
                               sizeof(key_object_size),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + to_string(status));
    }

    vector<unsigned char> key_object(key_object_size);
    BCRYPT_KEY_HANDLE h_key(nullptr);
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(kek.data()),
                                        static_cast<ULONG>(kek.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed: " + to_string(status));
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> encrypted(block.size());
    ULONG encrypted_size(0);
    status = BCryptEncrypt(key_guard.get(),
                           const_cast<PUCHAR>(block.data()),
                           static_cast<ULONG>(block.size()),
                           nullptr,
                           nullptr,
                           0,
                           encrypted.data(),
                           static_cast<ULONG>(encrypted.size()),
                           &encrypted_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptEncrypt failed: " + to_string(status));
    }

    encrypted.resize(encrypted_size);
    return encrypted;
}

vector<unsigned char> aesDecryptBlockEcb(vector<unsigned char> const &kek,
                                         vector<unsigned char> const &block)
{
    if (block.size() != 16)
    {
        throw runtime_error("AES block decryption requires a 16-byte block");
    }

    BCRYPT_ALG_HANDLE h_alg(nullptr);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + to_string(status));
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed: " + to_string(status));
    }

    ULONG key_object_size(0);
    ULONG result_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_size),
                               sizeof(key_object_size),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + to_string(status));
    }

    vector<unsigned char> key_object(key_object_size);
    BCRYPT_KEY_HANDLE h_key(nullptr);
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(kek.data()),
                                        static_cast<ULONG>(kek.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed: " + to_string(status));
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> decrypted(block.size());
    ULONG decrypted_size(0);
    status = BCryptDecrypt(key_guard.get(),
                           const_cast<PUCHAR>(block.data()),
                           static_cast<ULONG>(block.size()),
                           nullptr,
                           nullptr,
                           0,
                           decrypted.data(),
                           static_cast<ULONG>(decrypted.size()),
                           &decrypted_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDecrypt failed: " + to_string(status));
    }

    decrypted.resize(decrypted_size);
    return decrypted;
}

vector<unsigned char> aesKeyWrap(vector<unsigned char> const &kek,
                                 vector<unsigned char> const &plaintext)
{
    if (plaintext.empty() || (plaintext.size() % 8) != 0 || plaintext.size() < 16)
    {
        throw runtime_error("AES Key Wrap requires plaintext length to be a multiple of 8 bytes "
                            "and at least 16 bytes");
    }

    size_t const n = plaintext.size() / 8;
    vector<unsigned char> a(8, 0xA6);  // RFC 3394 default IV
    vector<vector<unsigned char>> r(n, vector<unsigned char>(8));
    for (size_t i = 0; i < n; ++i)
    {
        copy_n(plaintext.data() + i * 8, 8, r[i].data());
    }

    for (size_t j = 0; j < 6; ++j)
    {
        for (size_t i = 0; i < n; ++i)
        {
            vector<unsigned char> block(16);
            copy_n(a.data(), 8, block.data());
            copy_n(r[i].data(), 8, block.data() + 8);

            vector<unsigned char> encrypted = aesEncryptBlockEcb(kek, block);
            if (encrypted.size() != 16)
            {
                throw runtime_error("AES block encryption returned unexpected size");
            }

            copy_n(encrypted.data(), 8, a.data());
            copy_n(encrypted.data() + 8, 8, r[i].data());

            uint64_t t = static_cast<uint64_t>(n * j + (i + 1));
            for (size_t byte_index = 0; byte_index < 8; ++byte_index)
            {
                a[7 - byte_index] ^= static_cast<unsigned char>((t >> (8 * byte_index)) & 0xFF);
            }
        }
    }

    vector<unsigned char> wrapped;
    wrapped.reserve((n + 1) * 8);
    wrapped.insert(wrapped.end(), a.begin(), a.end());
    for (size_t i = 0; i < n; ++i)
    {
        wrapped.insert(wrapped.end(), r[i].begin(), r[i].end());
    }
    return wrapped;
}

vector<unsigned char> aesKeyUnwrap(vector<unsigned char> const &kek,
                                   vector<unsigned char> const &wrapped)
{
    if (wrapped.size() < 24 || (wrapped.size() % 8) != 0)
    {
        throw runtime_error("AES Key Unwrap requires input length to be a multiple of 8 bytes and "
                            "at least 24 bytes");
    }

    size_t const n = (wrapped.size() / 8) - 1;
    vector<unsigned char> a(8);
    copy_n(wrapped.data(), 8, a.data());

    vector<vector<unsigned char>> r(n, vector<unsigned char>(8));
    for (size_t i = 0; i < n; ++i)
    {
        copy_n(wrapped.data() + 8 + i * 8, 8, r[i].data());
    }

    for (int j = 5; j >= 0; --j)
    {
        for (size_t i = n; i > 0; --i)
        {
            uint64_t t = static_cast<uint64_t>(n * static_cast<size_t>(j) + i);

            vector<unsigned char> block(16);
            for (size_t byte_index = 0; byte_index < 8; ++byte_index)
            {
                block[byte_index] = static_cast<unsigned char>(
                    a[byte_index] ^
                    static_cast<unsigned char>((t >> (8 * (7 - byte_index))) & 0xFF));
            }
            copy_n(r[i - 1].data(), 8, block.data() + 8);

            vector<unsigned char> decrypted = aesDecryptBlockEcb(kek, block);
            if (decrypted.size() != 16)
            {
                throw runtime_error("AES block decryption returned unexpected size");
            }

            copy_n(decrypted.data(), 8, a.data());
            copy_n(decrypted.data() + 8, 8, r[i - 1].data());
        }
    }

    for (unsigned char byte : a)
    {
        if (byte != 0xA6)
        {
            throw runtime_error("AES key unwrap integrity check failed");
        }
    }

    vector<unsigned char> plaintext;
    plaintext.reserve(n * 8);
    for (size_t i = 0; i < n; ++i)
    {
        plaintext.insert(plaintext.end(), r[i].begin(), r[i].end());
    }
    return plaintext;
}

bool constantTimeEqual(vector<unsigned char> const &lhs, vector<unsigned char> const &rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    unsigned char diff = 0;
    for (size_t index = 0; index < lhs.size(); ++index)
    {
        diff |= static_cast<unsigned char>(lhs[index] ^ rhs[index]);
    }
    return diff == 0;
}

vector<unsigned char> computeHmac(wchar_t const *hash_algorithm,
                                  vector<unsigned char> const &key,
                                  vector<unsigned char> const &data,
                                  ULONG expected_hash_size)
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status =
        BCryptOpenAlgorithmProvider(&h_alg, hash_algorithm, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed");
    }
    AlgHandle alg_guard(h_alg);

    ULONG hash_object_length = 0;
    ULONG result_length = 0;
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_object_length),
                               sizeof(hash_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");
    }

    vector<unsigned char> hash_object(hash_object_length);
    BCRYPT_HASH_HANDLE h_hash = nullptr;
    status = BCryptCreateHash(alg_guard.get(),
                              &h_hash,
                              hash_object.empty() ? nullptr : hash_object.data(),
                              static_cast<ULONG>(hash_object.size()),
                              const_cast<PUCHAR>(key.data()),
                              static_cast<ULONG>(key.size()),
                              0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptCreateHash failed");
    }
    HashHandle hash_guard(h_hash);

    if (!data.empty())
    {
        status = BCryptHashData(h_hash,
                                const_cast<PUCHAR>(data.data()),
                                static_cast<ULONG>(data.size()),
                                0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptHashData failed");
        }
    }

    vector<unsigned char> digest(expected_hash_size);
    status = BCryptFinishHash(h_hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinishHash failed");
    }

    return digest;
}

pair<vector<unsigned char>, vector<unsigned char>>
aesGcmEncrypt(vector<unsigned char> const &cek,
              vector<unsigned char> const &iv,
              vector<unsigned char> const &plaintext,
              vector<unsigned char> const &aad)
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed");
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed");
    }

    ULONG key_object_length = 0;
    ULONG result_length = 0;
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_length),
                               sizeof(key_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");
    }

    vector<unsigned char> key_object(key_object_length);
    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(cek.data()),
                                        static_cast<ULONG>(cek.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed");
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> tag(16);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(iv.data());
    auth_info.cbNonce = static_cast<ULONG>(iv.size());
    auth_info.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    auth_info.pbTag = tag.data();
    auth_info.cbTag = static_cast<ULONG>(tag.size());

    ULONG ciphertext_size = 0;
    status = BCryptEncrypt(key_guard.get(),
                           plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                           static_cast<ULONG>(plaintext.size()),
                           &auth_info,
                           nullptr,
                           0,
                           nullptr,
                           0,
                           &ciphertext_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptEncrypt(size query) failed");
    }

    vector<unsigned char> ciphertext(ciphertext_size);
    status = BCryptEncrypt(key_guard.get(),
                           plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                           static_cast<ULONG>(plaintext.size()),
                           &auth_info,
                           nullptr,
                           0,
                           ciphertext.data(),
                           static_cast<ULONG>(ciphertext.size()),
                           &ciphertext_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptEncrypt failed");
    }

    ciphertext.resize(ciphertext_size);
    return {ciphertext, tag};
}

vector<unsigned char> aesGcmDecrypt(vector<unsigned char> const &cek,
                                    vector<unsigned char> const &iv,
                                    vector<unsigned char> const &ciphertext,
                                    vector<unsigned char> const &aad,
                                    vector<unsigned char> const &tag)
{
    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed");
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed");
    }

    ULONG key_object_length = 0;
    ULONG result_length = 0;
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_length),
                               sizeof(key_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");
    }

    vector<unsigned char> key_object(key_object_length);
    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(cek.data()),
                                        static_cast<ULONG>(cek.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed");
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> mutable_tag(tag);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(iv.data());
    auth_info.cbNonce = static_cast<ULONG>(iv.size());
    auth_info.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    auth_info.pbTag = mutable_tag.empty() ? nullptr : mutable_tag.data();
    auth_info.cbTag = static_cast<ULONG>(mutable_tag.size());

    ULONG plaintext_size = 0;
    status = BCryptDecrypt(key_guard.get(),
                           ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                           static_cast<ULONG>(ciphertext.size()),
                           &auth_info,
                           nullptr,
                           0,
                           nullptr,
                           0,
                           &plaintext_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDecrypt(size query) failed");
    }

    vector<unsigned char> plaintext(plaintext_size);
    status = BCryptDecrypt(key_guard.get(),
                           ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                           static_cast<ULONG>(ciphertext.size()),
                           &auth_info,
                           nullptr,
                           0,
                           plaintext.data(),
                           static_cast<ULONG>(plaintext.size()),
                           &plaintext_size,
                           0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDecrypt failed");
    }

    plaintext.resize(plaintext_size);
    return plaintext;
}

/// Import an EC key for ECDH key agreement using the BCRYPT_ECDH_Pxxx algorithm provider.
KeyHandle importECDHKey(ECKey const &ec_key, bool require_private)
{
    auto const &curve_name = ec_key.getCurveName();
    wchar_t const *alg_name = nullptr;
    ULONG private_magic = 0;
    ULONG public_magic = 0;

    if (curve_name == "P-256")
    {
        alg_name = BCRYPT_ECDH_P256_ALGORITHM;
        private_magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        public_magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    }
    else if (curve_name == "P-384")
    {
        alg_name = BCRYPT_ECDH_P384_ALGORITHM;
        private_magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        public_magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
    }
    else if (curve_name == "P-521")
    {
        alg_name = BCRYPT_ECDH_P521_ALGORITHM;
        private_magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        public_magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
    }
    else
    {
        throw runtime_error("Unsupported EC curve for ECDH: " + curve_name);
    }

    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, alg_name, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider (ECDH) failed");
    }
    AlgHandle alg_guard(h_alg);

    vector<unsigned char> blob;
    LPCWSTR blob_type = nullptr;
    if (require_private)
    {
        blob = buildEcPrivateBlob(ec_key, private_magic);
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
    }
    else
    {
        blob = buildEcPublicBlob(ec_key, public_magic);
        blob_type = BCRYPT_ECCPUBLIC_BLOB;
    }

    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = BCryptImportKeyPair(alg_guard.get(),
                                 nullptr,
                                 blob_type,
                                 &h_key,
                                 blob.data(),
                                 static_cast<ULONG>(blob.size()),
                                 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptImportKeyPair (ECDH) failed");
    }
    return KeyHandle(h_key);
}

/// Perform ECDH key agreement and return the shared secret as a big-endian byte vector.
/// private_key must be an ECKey with private material; public_key must be an ECKey.
vector<unsigned char> computeECDHSharedSecret(Key *private_key, Key *public_key)
{
    auto ec_private = dynamic_cast<ECKey *>(private_key);
    auto ec_public = dynamic_cast<ECKey *>(public_key);
    if (!ec_private || !ec_public)
    {
        throw runtime_error("ECDH key agreement requires EC keys");
    }

    KeyHandle priv_handle = importECDHKey(*ec_private, true);
    KeyHandle pub_handle = importECDHKey(*ec_public, false);

    BCRYPT_SECRET_HANDLE h_secret = nullptr;
    NTSTATUS status = BCryptSecretAgreement(static_cast<BCRYPT_KEY_HANDLE>(priv_handle.get()),
                                            static_cast<BCRYPT_KEY_HANDLE>(pub_handle.get()),
                                            &h_secret,
                                            0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSecretAgreement failed");
    }
    SecretHandle secret_guard(h_secret);

    ULONG derived_size = 0;
    status = BCryptDeriveKey(static_cast<BCRYPT_SECRET_HANDLE>(secret_guard.get()),
                             BCRYPT_KDF_RAW_SECRET,
                             nullptr,
                             nullptr,
                             0,
                             &derived_size,
                             0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDeriveKey (size query) failed");
    }

    vector<unsigned char> shared_secret(derived_size);
    status = BCryptDeriveKey(static_cast<BCRYPT_SECRET_HANDLE>(secret_guard.get()),
                             BCRYPT_KDF_RAW_SECRET,
                             nullptr,
                             shared_secret.data(),
                             static_cast<ULONG>(shared_secret.size()),
                             &derived_size,
                             0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDeriveKey failed");
    }
    shared_secret.resize(derived_size);

    // CNG returns the raw ECDH secret in little-endian byte order.
    // JOSE (RFC 7518) requires big-endian, so reverse the bytes.
    reverse(shared_secret.begin(), shared_secret.end());
    return shared_secret;
}

/// AES-GCM key wrap: returns [IV (12 bytes)][ciphertext][tag (16 bytes)].
vector<unsigned char> aesGcmKeyWrapHelper(vector<unsigned char> const &kek,
                                          vector<unsigned char> const &cek)
{
    vector<unsigned char> iv(12);
    NTSTATUS status = BCryptGenRandom(nullptr,
                                      iv.data(),
                                      static_cast<ULONG>(iv.size()),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenRandom failed");
    }

    auto [ciphertext, tag] = aesGcmEncrypt(kek, iv, cek, {});

    vector<unsigned char> result;
    result.reserve(iv.size() + ciphertext.size() + tag.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

/// AES-GCM key unwrap.
/// If iv_opt and tag_opt are present they are used directly; otherwise iv and tag are
/// extracted from the first 12 / last 16 bytes of wrapped_cek.
vector<unsigned char> aesGcmKeyUnwrapHelper(vector<unsigned char> const &kek,
                                            vector<unsigned char> const &wrapped_cek,
                                            optional<vector<unsigned char>> const &iv_opt,
                                            optional<vector<unsigned char>> const &tag_opt)
{
    if (iv_opt.has_value() && tag_opt.has_value())
    {
        return aesGcmDecrypt(kek, *iv_opt, wrapped_cek, {}, *tag_opt);
    }

    constexpr size_t iv_size = 12;
    constexpr size_t tag_size = 16;
    if (wrapped_cek.size() < iv_size + tag_size)
    {
        throw runtime_error("AES-GCM key unwrap: wrapped data too short");
    }
    vector<unsigned char> iv(wrapped_cek.begin(), wrapped_cek.begin() + iv_size);
    vector<unsigned char> tag(wrapped_cek.end() - tag_size, wrapped_cek.end());
    vector<unsigned char> ciphertext(wrapped_cek.begin() + iv_size, wrapped_cek.end() - tag_size);
    return aesGcmDecrypt(kek, iv, ciphertext, {}, tag);
}

pair<vector<unsigned char>, vector<unsigned char>>
aesCbcHmacEncrypt(size_t mac_key_size,
                  size_t enc_key_size,
                  wchar_t const *hmac_alg,
                  size_t tag_size,
                  vector<unsigned char> const &cek,
                  vector<unsigned char> const &iv,
                  vector<unsigned char> const &plaintext,
                  vector<unsigned char> const &aad)
{
    if (cek.size() != (mac_key_size + enc_key_size))
    {
        throw runtime_error("Invalid CEK size for AES-CBC-HMAC algorithm");
    }

    vector<unsigned char> mac_key(cek.begin(), cek.begin() + static_cast<ptrdiff_t>(mac_key_size));
    vector<unsigned char> enc_key(cek.begin() + static_cast<ptrdiff_t>(mac_key_size), cek.end());

    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed");
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed");
    }

    ULONG key_object_length = 0;
    ULONG result_length = 0;
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_length),
                               sizeof(key_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");
    }

    vector<unsigned char> key_object(key_object_length);
    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(enc_key.data()),
                                        static_cast<ULONG>(enc_key.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed");
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> mutable_iv(iv);
    ULONG ciphertext_size = 0;
    status = BCryptEncrypt(key_guard.get(),
                           plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                           static_cast<ULONG>(plaintext.size()),
                           nullptr,
                           mutable_iv.empty() ? nullptr : mutable_iv.data(),
                           static_cast<ULONG>(mutable_iv.size()),
                           nullptr,
                           0,
                           &ciphertext_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptEncrypt(size query) failed");
    }

    mutable_iv = iv;
    vector<unsigned char> ciphertext(ciphertext_size);
    status = BCryptEncrypt(key_guard.get(),
                           plaintext.empty() ? nullptr : const_cast<PUCHAR>(plaintext.data()),
                           static_cast<ULONG>(plaintext.size()),
                           nullptr,
                           mutable_iv.empty() ? nullptr : mutable_iv.data(),
                           static_cast<ULONG>(mutable_iv.size()),
                           ciphertext.data(),
                           static_cast<ULONG>(ciphertext.size()),
                           &ciphertext_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptEncrypt failed");
    }
    ciphertext.resize(ciphertext_size);

    array<unsigned char, 8> al{};
    uint64_t aad_bits = static_cast<uint64_t>(aad.size()) * 8ULL;
    for (size_t index = 0; index < al.size(); ++index)
    {
        al[al.size() - 1 - index] = static_cast<unsigned char>((aad_bits >> (index * 8)) & 0xFF);
    }

    vector<unsigned char> mac_input;
    mac_input.reserve(aad.size() + iv.size() + ciphertext.size() + al.size());
    mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    mac_input.insert(mac_input.end(), iv.begin(), iv.end());
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    mac_input.insert(mac_input.end(), al.begin(), al.end());

    ULONG hash_size = 32;
    if (wcscmp(hmac_alg, BCRYPT_SHA384_ALGORITHM) == 0)
    {
        hash_size = 48;
    }
    else if (wcscmp(hmac_alg, BCRYPT_SHA512_ALGORITHM) == 0)
    {
        hash_size = 64;
    }

    vector<unsigned char> full_tag(computeHmac(hmac_alg, mac_key, mac_input, hash_size));
    vector<unsigned char> truncated_tag(full_tag.begin(),
                                        full_tag.begin() + static_cast<ptrdiff_t>(tag_size));
    return {ciphertext, truncated_tag};
}

vector<unsigned char> aesCbcHmacDecrypt(size_t mac_key_size,
                                        size_t enc_key_size,
                                        wchar_t const *hmac_alg,
                                        size_t tag_size,
                                        vector<unsigned char> const &cek,
                                        vector<unsigned char> const &iv,
                                        vector<unsigned char> const &ciphertext,
                                        vector<unsigned char> const &aad,
                                        vector<unsigned char> const &tag)
{
    if (cek.size() != (mac_key_size + enc_key_size))
    {
        throw runtime_error("Invalid CEK size for AES-CBC-HMAC algorithm");
    }
    if (tag.size() != tag_size)
    {
        throw runtime_error("Invalid tag size for AES-CBC-HMAC algorithm");
    }

    vector<unsigned char> mac_key(cek.begin(), cek.begin() + static_cast<ptrdiff_t>(mac_key_size));
    vector<unsigned char> enc_key(cek.begin() + static_cast<ptrdiff_t>(mac_key_size), cek.end());

    array<unsigned char, 8> al{};
    uint64_t aad_bits = static_cast<uint64_t>(aad.size()) * 8ULL;
    for (size_t index = 0; index < al.size(); ++index)
    {
        al[al.size() - 1 - index] = static_cast<unsigned char>((aad_bits >> (index * 8)) & 0xFF);
    }

    vector<unsigned char> mac_input;
    mac_input.reserve(aad.size() + iv.size() + ciphertext.size() + al.size());
    mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    mac_input.insert(mac_input.end(), iv.begin(), iv.end());
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    mac_input.insert(mac_input.end(), al.begin(), al.end());

    ULONG hash_size = 32;
    if (wcscmp(hmac_alg, BCRYPT_SHA384_ALGORITHM) == 0)
    {
        hash_size = 48;
    }
    else if (wcscmp(hmac_alg, BCRYPT_SHA512_ALGORITHM) == 0)
    {
        hash_size = 64;
    }

    vector<unsigned char> full_tag(computeHmac(hmac_alg, mac_key, mac_input, hash_size));
    vector<unsigned char> expected_tag(full_tag.begin(),
                                       full_tag.begin() + static_cast<ptrdiff_t>(tag_size));
    if (!constantTimeEqual(expected_tag, tag))
    {
        throw runtime_error("AES-CBC-HMAC authentication tag verification failed");
    }

    BCRYPT_ALG_HANDLE h_alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed");
    }
    AlgHandle alg_guard(h_alg);

    status =
        BCryptSetProperty(alg_guard.get(),
                          BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_CBC)),
                          static_cast<ULONG>((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)),
                          0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptSetProperty(BCRYPT_CHAINING_MODE) failed");
    }

    ULONG key_object_length = 0;
    ULONG result_length = 0;
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_length),
                               sizeof(key_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed");
    }

    vector<unsigned char> key_object(key_object_length);
    BCRYPT_KEY_HANDLE h_key = nullptr;
    status = BCryptGenerateSymmetricKey(alg_guard.get(),
                                        &h_key,
                                        key_object.empty() ? nullptr : key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(enc_key.data()),
                                        static_cast<ULONG>(enc_key.size()),
                                        0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateSymmetricKey failed");
    }
    KeyHandle key_guard(h_key);

    vector<unsigned char> mutable_iv(iv);
    ULONG plaintext_size = 0;
    status = BCryptDecrypt(key_guard.get(),
                           ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                           static_cast<ULONG>(ciphertext.size()),
                           nullptr,
                           mutable_iv.empty() ? nullptr : mutable_iv.data(),
                           static_cast<ULONG>(mutable_iv.size()),
                           nullptr,
                           0,
                           &plaintext_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDecrypt(size query) failed");
    }

    mutable_iv = iv;
    vector<unsigned char> plaintext(plaintext_size);
    status = BCryptDecrypt(key_guard.get(),
                           ciphertext.empty() ? nullptr : const_cast<PUCHAR>(ciphertext.data()),
                           static_cast<ULONG>(ciphertext.size()),
                           nullptr,
                           mutable_iv.empty() ? nullptr : mutable_iv.data(),
                           static_cast<ULONG>(mutable_iv.size()),
                           plaintext.data(),
                           static_cast<ULONG>(plaintext.size()),
                           &plaintext_size,
                           BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptDecrypt failed");
    }

    plaintext.resize(plaintext_size);
    return plaintext;
}

}  // namespace

CNGRSAKey::CNGRSAKey(vector<unsigned char> n,
                     vector<unsigned char> e,
                     vector<unsigned char> d,
                     vector<unsigned char> p,
                     vector<unsigned char> q,
                     vector<unsigned char> dp,
                     vector<unsigned char> dq,
                     vector<unsigned char> iqmp,
                     vector<unsigned char> public_blob,
                     vector<unsigned char> private_blob,
                     BCRYPT_KEY_HANDLE key_handle /* = nullptr*/,
                     BCRYPT_ALG_HANDLE alg_handle /* = nullptr*/)
    : public_blob_(std::move(public_blob)), private_blob_(std::move(private_blob)),
      n_(std::move(n)), e_(std::move(e)), d_(std::move(d)), p_(std::move(p)), q_(std::move(q)),
      dp_(std::move(dp)), dq_(std::move(dq)), iqmp_(std::move(iqmp)), key_handle_(key_handle),
      alg_handle_(alg_handle)
{
}

vector<unsigned char> CNGRSAKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> CNGRSAKey::getPrivateBlob() const
{
    return private_blob_;
}

bool CNGRSAKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Private::Key> CNGRSAKey::clone() const
{
    // CNG handles are not duplicable; the clone carries only the serialisable fields.
    return make_unique<CNGRSAKey>(n_, e_, d_, p_, q_, dp_, dq_, iqmp_, public_blob_, private_blob_);
}

// CNGECKey implementation
CNGECKey::CNGECKey(string curve_name,
                   vector<unsigned char> const &x,
                   vector<unsigned char> const &y,
                   vector<unsigned char> const &d,
                   vector<unsigned char> public_blob,
                   vector<unsigned char> private_blob,
                   BCRYPT_KEY_HANDLE key_handle,
                   BCRYPT_ALG_HANDLE alg_handle)
    : ECKey(curve_name), x_(x), y_(y), d_(d), public_blob_(std::move(public_blob)),
      private_blob_(std::move(private_blob)), key_handle_(key_handle), alg_handle_(alg_handle)
{
}

vector<unsigned char> CNGECKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> CNGECKey::getPrivateBlob() const
{
    return private_blob_;
}

bool CNGECKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Private::Key> CNGECKey::clone() const
{
    // CNG handles are not duplicable; the clone carries only the serialisable fields.
    return make_unique<CNGECKey>(getCurveName(), x_, y_, d_, public_blob_, private_blob_);
}

// CNGRSAKey parameter accessors
vector<unsigned char> CNGRSAKey::getN() const
{
    return n_;
}
vector<unsigned char> CNGRSAKey::getE() const
{
    return e_;
}
vector<unsigned char> CNGRSAKey::getD() const
{
    return d_;
}
vector<unsigned char> CNGRSAKey::getP() const
{
    return p_;
}
vector<unsigned char> CNGRSAKey::getQ() const
{
    return q_;
}
vector<unsigned char> CNGRSAKey::getDp() const
{
    return dp_;
}
vector<unsigned char> CNGRSAKey::getDq() const
{
    return dq_;
}
vector<unsigned char> CNGRSAKey::getQi() const
{
    return iqmp_;
}

unique_ptr<Key> CNGBackEnd::generateRSA(unsigned int bits) const
{
    unsigned int const max_attempts = static_cast<unsigned int>(JOSE_RSA_GENERATION_MAX_ATTEMPTS);
    string last_reason;

    for (unsigned int attempt = 0; attempt < max_attempts; ++attempt)
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(hAlg);

        BCRYPT_KEY_HANDLE hKey = nullptr;
        status = BCryptGenerateKeyPair(alg_guard.get(), &hKey, bits, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptGenerateKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(hKey);

        status = BCryptFinalizeKeyPair(key_guard.get(), 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptFinalizeKeyPair failed: " + getErrorString());
        }

        // Export public key
        ULONG pub_size = 0;
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_RSAPUBLIC_BLOB,
                                 nullptr,
                                 0,
                                 &pub_size,
                                 0);
        if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
        {
            throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
        }

        vector<unsigned char> pub_blob(pub_size);
        ULONG pub_blob_size = static_cast<ULONG>(pub_blob.size());
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_RSAPUBLIC_BLOB,
                                 pub_blob.data(),
                                 pub_blob_size,
                                 &pub_size,
                                 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
        }

        // Parse public blob for n and e
        vector<unsigned char> n, e;
        if (pub_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
        {
            BCRYPT_RSAKEY_BLOB header{};
            copy_n(pub_blob.data(), sizeof(header), reinterpret_cast<unsigned char *>(&header));

            // Verify the blob is large enough to hold all fields described by the header
            size_t const expected_pub_size =
                sizeof(BCRYPT_RSAKEY_BLOB) + header.cbPublicExp + header.cbModulus;
            if (pub_blob.size() < expected_pub_size)
            {
                throw runtime_error("BCryptExportKey returned a truncated public blob");
            }

            unsigned char const *ptr = pub_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            if (header.cbPublicExp)
            {
                e.assign(ptr, ptr + header.cbPublicExp);
                ptr += header.cbPublicExp;
            }
            if (header.cbModulus)
            {
                n.assign(ptr, ptr + header.cbModulus);
                ptr += header.cbModulus;
            }
        }

        // Export private key — must use BCRYPT_RSAFULLPRIVATE_BLOB to get all CRT
        // parameters (dp, dq, iqmp, d). BCRYPT_RSAPRIVATE_BLOB only contains p and q.
        ULONG priv_size = 0;
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_RSAFULLPRIVATE_BLOB,
                                 nullptr,
                                 0,
                                 &priv_size,
                                 0);
        vector<unsigned char> priv_blob;
        if (BCRYPT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL)
        {
            priv_blob.resize(priv_size);
            ULONG priv_blob_size = static_cast<ULONG>(priv_blob.size());
            status = BCryptExportKey(key_guard.get(),
                                     nullptr,
                                     BCRYPT_RSAFULLPRIVATE_BLOB,
                                     priv_blob.data(),
                                     priv_blob_size,
                                     &priv_size,
                                     0);
            if (!BCRYPT_SUCCESS(status))
            {
                priv_blob.clear();
            }
            else
            {
                priv_blob.resize(priv_size);
            }
        }

        // Parse private blob for remaining parameters
        vector<unsigned char> d, p, q, dp, dq, iqmp;
        if (priv_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
        {
            BCRYPT_RSAKEY_BLOB header{};
            copy_n(priv_blob.data(), sizeof(header), reinterpret_cast<unsigned char *>(&header));

            // Full private blob layout (BCRYPT_RSAFULLPRIVATE_BLOB, Magic =
            // BCRYPT_RSAFULLPRIVATE_MAGIC):
            //   PublicExponent   (cbPublicExp bytes)
            //   Modulus          (cbModulus bytes)
            //   Prime1 / p       (cbPrime1 bytes)
            //   Prime2 / q       (cbPrime2 bytes)
            //   Exponent1 / dp   (cbPrime1 bytes)   -- d mod (p-1)
            //   Exponent2 / dq   (cbPrime2 bytes)   -- d mod (q-1)
            //   Coefficient/iqmp (cbPrime1 bytes)   -- q^-1 mod p
            //   PrivateExp / d   (cbModulus bytes)
            // See:
            // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
            size_t const expected_priv_size = sizeof(BCRYPT_RSAKEY_BLOB) + header.cbPublicExp +
                                              2 * header.cbModulus + 3 * header.cbPrime1 +
                                              2 * header.cbPrime2;
            if (priv_blob.size() < expected_priv_size)
            {
                priv_blob.clear();
            }
            else
            {
                unsigned char const *ptr = priv_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
                ptr += header.cbPublicExp;
                ptr += header.cbModulus;
                if (header.cbPrime1)
                {
                    p.assign(ptr, ptr + header.cbPrime1);
                    ptr += header.cbPrime1;
                }
                if (header.cbPrime2)
                {
                    q.assign(ptr, ptr + header.cbPrime2);
                    ptr += header.cbPrime2;
                }
                if (header.cbPrime1)
                {
                    dp.assign(ptr, ptr + header.cbPrime1);
                    ptr += header.cbPrime1;
                }
                if (header.cbPrime2)
                {
                    dq.assign(ptr, ptr + header.cbPrime2);
                    ptr += header.cbPrime2;
                }
                if (header.cbPrime1)
                {
                    iqmp.assign(ptr, ptr + header.cbPrime1);
                    ptr += header.cbPrime1;
                }
                if (header.cbModulus)
                {
                    d.assign(ptr, ptr + header.cbModulus);
                    ptr += header.cbModulus;
                }
            }
        }

        // If we didn't get n/e from pub_blob, try to get from priv_blob header
        if (n.empty() && !priv_blob.empty() && priv_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
        {
            auto hdr2 = reinterpret_cast<BCRYPT_RSAKEY_BLOB const *>(priv_blob.data());
            unsigned char const *ptr2 = priv_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            if (hdr2->cbPublicExp)
            {
                e.assign(ptr2, ptr2 + hdr2->cbPublicExp);
                ptr2 += hdr2->cbPublicExp;
            }
            if (hdr2->cbModulus)
            {
                n.assign(ptr2, ptr2 + hdr2->cbModulus);
                ptr2 += hdr2->cbModulus;
            }
        }

        bool const has_full_private = !d.empty() && !p.empty() && !q.empty() && !dp.empty() &&
                                      !dq.empty() && !iqmp.empty() && !priv_blob.empty();
        if (has_full_private)
        {
            // Transfer ownership of the CNG handles to the key wrapper.
            // The CNGRSAKey destructor will clean them up via the guard members.
            return make_unique<CNGRSAKey>(std::move(n),
                                          std::move(e),
                                          std::move(d),
                                          std::move(p),
                                          std::move(q),
                                          std::move(dp),
                                          std::move(dq),
                                          std::move(iqmp),
                                          pub_blob,
                                          priv_blob,
                                          key_guard.release(),
                                          alg_guard.release());
        }

        last_reason = "incomplete private RSA export from CNG provider";
    }

    throw runtime_error("Failed to generate a complete RSA private key after " +
                        to_string(max_attempts) + " attempts: " + last_reason);
}

unique_ptr<Key> CNGBackEnd::generateRSA(vector<unsigned char> const &n_bytes,
                                        vector<unsigned char> const &e_bytes,
                                        vector<unsigned char> const &d_bytes,
                                        vector<unsigned char> const &p_bytes,
                                        vector<unsigned char> const &q_bytes,
                                        vector<unsigned char> const &dp_bytes,
                                        vector<unsigned char> const &dq_bytes,
                                        vector<unsigned char> const &qi_bytes) const
{
    if (n_bytes.empty() || e_bytes.empty())
    {
        throw runtime_error("RSA import requires at least modulus (n) and public exponent (e)");
    }

    // CNG only supports public-only or full-CRT private import; a bare-d key (without
    // the CRT parameters) cannot be imported because CNG needs p, q, dp, dq, qi to operate.
    bool const has_crt = !d_bytes.empty() && !p_bytes.empty() && !q_bytes.empty() &&
                         !dp_bytes.empty() && !dq_bytes.empty() && !qi_bytes.empty();
    if (!d_bytes.empty() && !has_crt)
    {
        throw runtime_error("CNG RSA import requires either a public key (n, e) or a full "
                            "private key with CRT parameters (n, e, d, p, q, dp, dq, qi)");
    }

    // Build the BCRYPT_RSAKEY_BLOB header followed by the key material.
    // Full private blob layout (BCRYPT_RSAFULLPRIVATE_BLOB):
    //   BCRYPT_RSAKEY_BLOB header
    //   PublicExponent  (cbPublicExp bytes)
    //   Modulus         (cbModulus   bytes)
    //   Prime1 / p      (cbPrime1    bytes)
    //   Prime2 / q      (cbPrime2    bytes)
    //   Exponent1 / dp  (cbPrime1    bytes)  -- d mod (p-1)
    //   Exponent2 / dq  (cbPrime2    bytes)  -- d mod (q-1)
    //   Coefficient/qi  (cbPrime1    bytes)  -- q^-1 mod p
    //   PrivateExp / d  (cbModulus   bytes)
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = has_crt ? BCRYPT_RSAFULLPRIVATE_MAGIC : BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = static_cast<ULONG>(n_bytes.size() * 8);
    header.cbPublicExp = static_cast<ULONG>(e_bytes.size());
    header.cbModulus = static_cast<ULONG>(n_bytes.size());
    header.cbPrime1 = has_crt ? static_cast<ULONG>(p_bytes.size()) : 0;
    header.cbPrime2 = has_crt ? static_cast<ULONG>(q_bytes.size()) : 0;

    vector<unsigned char> blob(sizeof(BCRYPT_RSAKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), e_bytes.begin(), e_bytes.end());
    blob.insert(blob.end(), n_bytes.begin(), n_bytes.end());
    if (has_crt)
    {
        blob.insert(blob.end(), p_bytes.begin(), p_bytes.end());
        blob.insert(blob.end(), q_bytes.begin(), q_bytes.end());
        blob.insert(blob.end(), dp_bytes.begin(), dp_bytes.end());
        blob.insert(blob.end(), dq_bytes.begin(), dq_bytes.end());
        blob.insert(blob.end(), qi_bytes.begin(), qi_bytes.end());
        blob.insert(blob.end(), d_bytes.begin(), d_bytes.end());
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    LPCWSTR const blob_type = has_crt ? BCRYPT_RSAFULLPRIVATE_BLOB : BCRYPT_RSAPUBLIC_BLOB;
    status = BCryptImportKeyPair(alg_guard.get(),
                                 nullptr,
                                 blob_type,
                                 &hKey,
                                 blob.data(),
                                 static_cast<ULONG>(blob.size()),
                                 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    return make_unique<CNGRSAKey>(n_bytes,
                                  e_bytes,
                                  d_bytes,
                                  p_bytes,
                                  q_bytes,
                                  dp_bytes,
                                  dq_bytes,
                                  qi_bytes,
                                  vector<unsigned char>{},
                                  vector<unsigned char>{},
                                  key_guard.release(),
                                  alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateEC(string const &curve) const
{
    LPCWSTR alg = nullptr;
    string curve_name;
    if (curve == "P-256" || curve == "prime256v1")
    {
        alg = BCRYPT_ECDH_P256_ALGORITHM;
        curve_name = "P-256";
    }
    else if (curve == "P-384" || curve == "secp384r1")
    {
        alg = BCRYPT_ECDH_P384_ALGORITHM;
        curve_name = "P-384";
    }
    else if (curve == "P-521" || curve == "secp521r1")
    {
        alg = BCRYPT_ECDH_P521_ALGORITHM;
        curve_name = "P-521";
    }
    else
    {
        throw runtime_error("Unsupported curve: " + curve);
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateKeyPair(alg_guard.get(), &hKey, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    status = BCryptFinalizeKeyPair(key_guard.get(), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinalizeKeyPair failed: " + getErrorString());
    }

    // Export public key
    ULONG pub_size = 0;
    status =
        BCryptExportKey(key_guard.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &pub_size, 0);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    vector<unsigned char> pub_blob(pub_size);
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_ECCPUBLIC_BLOB,
                             pub_blob.data(),
                             static_cast<ULONG>(pub_blob.size()),
                             &pub_size,
                             0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    // Parse x and y from the public blob.
    // BCRYPT_ECCKEY_BLOB layout (BCRYPT_ECCPUBLIC_BLOB):
    //   Magic  (ULONG)           -- e.g. BCRYPT_ECDH_PUBLIC_P256_MAGIC
    //   cbKey  (ULONG)           -- byte length of each coordinate
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    vector<unsigned char> x, y;
    if (pub_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB))
    {
        BCRYPT_ECCKEY_BLOB ecc_header{};
        copy_n(pub_blob.data(), sizeof(ecc_header), reinterpret_cast<unsigned char *>(&ecc_header));

        size_t const expected_ecc_pub_size = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ecc_header.cbKey;
        if (pub_blob.size() < expected_ecc_pub_size)
        {
            throw runtime_error("BCryptExportKey returned a truncated ECC public blob");
        }

        unsigned char const *ptr = pub_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        x.assign(ptr, ptr + ecc_header.cbKey);
        ptr += ecc_header.cbKey;
        y.assign(ptr, ptr + ecc_header.cbKey);
    }

    // Export private key
    ULONG priv_size = 0;
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_ECCPRIVATE_BLOB,
                             nullptr,
                             0,
                             &priv_size,
                             0);
    vector<unsigned char> priv_blob;
    if (BCRYPT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL)
    {
        priv_blob.resize(priv_size);
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_ECCPRIVATE_BLOB,
                                 priv_blob.data(),
                                 static_cast<ULONG>(priv_blob.size()),
                                 &priv_size,
                                 0);
        if (!BCRYPT_SUCCESS(status))
        {
            priv_blob.clear();
        }
        else
        {
            priv_blob.resize(priv_size);
        }
    }

    // Parse d from the private blob.
    // BCRYPT_ECCKEY_BLOB layout (BCRYPT_ECCPRIVATE_BLOB):
    //   Magic  (ULONG)
    //   cbKey  (ULONG)    -- byte length of each coordinate / scalar
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    //   d      (cbKey bytes)  -- private key scalar
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    vector<unsigned char> d;
    if (priv_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB))
    {
        BCRYPT_ECCKEY_BLOB ecc_priv_header{};
        copy_n(priv_blob.data(),
               sizeof(ecc_priv_header),
               reinterpret_cast<unsigned char *>(&ecc_priv_header));

        size_t const expected_ecc_priv_size =
            sizeof(BCRYPT_ECCKEY_BLOB) + 3 * ecc_priv_header.cbKey;
        if (priv_blob.size() < expected_ecc_priv_size)
        {
            priv_blob.clear();
        }
        else
        {
            // skip X and Y (already have them from public blob)
            unsigned char const *ptr =
                priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ecc_priv_header.cbKey;
            d.assign(ptr, ptr + ecc_priv_header.cbKey);
        }
    }

    // Transfer ownership of the CNG handles to the key wrapper.
    return make_unique<CNGECKey>(curve_name,
                                 x,
                                 y,
                                 d,
                                 std::move(pub_blob),
                                 std::move(priv_blob),
                                 key_guard.release(),
                                 alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateEC(string const &curve,
                                       vector<unsigned char> const &x_bytes,
                                       vector<unsigned char> const &y_bytes,
                                       vector<unsigned char> const &d_bytes) const
{
    if (x_bytes.empty() || y_bytes.empty())
    {
        throw runtime_error("EC import requires both x and y coordinates");
    }

    // Resolve the curve to its CNG algorithm identifier and the two magic values
    // (public and private) used in BCRYPT_ECCKEY_BLOB.
    // BCRYPT_ECCKEY_BLOB layout:
    //   Magic  (ULONG)  -- identifies curve + public/private
    //   cbKey  (ULONG)  -- byte length of each coordinate / scalar
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    //   [d     (cbKey bytes)]  -- only present in BCRYPT_ECCPRIVATE_BLOB
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    LPCWSTR alg_id = nullptr;
    ULONG pub_magic = 0;
    ULONG priv_magic = 0;
    string curve_name;

    if (curve == "P-256" || curve == "prime256v1")
    {
        alg_id = BCRYPT_ECDH_P256_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        curve_name = "P-256";
    }
    else if (curve == "P-384" || curve == "secp384r1")
    {
        alg_id = BCRYPT_ECDH_P384_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        curve_name = "P-384";
    }
    else if (curve == "P-521" || curve == "secp521r1")
    {
        alg_id = BCRYPT_ECDH_P521_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        curve_name = "P-521";
    }
    else
    {
        throw runtime_error("Unsupported EC curve: " + curve);
    }

    bool const has_private = !d_bytes.empty();

    // Build the import blob
    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = has_private ? priv_magic : pub_magic;
    header.cbKey = static_cast<ULONG>(x_bytes.size());

    vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), x_bytes.begin(), x_bytes.end());
    blob.insert(blob.end(), y_bytes.begin(), y_bytes.end());
    if (has_private)
    {
        blob.insert(blob.end(), d_bytes.begin(), d_bytes.end());
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg_id, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    LPCWSTR const blob_type = has_private ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB;
    status = BCryptImportKeyPair(alg_guard.get(),
                                 nullptr,
                                 blob_type,
                                 &hKey,
                                 blob.data(),
                                 static_cast<ULONG>(blob.size()),
                                 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    // Reconstruct the raw blobs in the same format that generateEC(curve) produces
    // so that getPublicBlob() / getPrivateBlob() remain consistent.
    ULONG const cb_key = static_cast<ULONG>(x_bytes.size());

    vector<unsigned char> pub_blob(sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb_key);
    BCRYPT_ECCKEY_BLOB pub_hdr{};
    pub_hdr.dwMagic = pub_magic;
    pub_hdr.cbKey = cb_key;
    copy_n(reinterpret_cast<unsigned char const *>(&pub_hdr), sizeof(pub_hdr), pub_blob.data());
    unsigned char *pub_ptr = pub_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    copy(x_bytes.begin(), x_bytes.end(), pub_ptr);
    copy(y_bytes.begin(), y_bytes.end(), pub_ptr + cb_key);

    vector<unsigned char> priv_blob;
    if (has_private)
    {
        priv_blob.resize(sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cb_key);
        BCRYPT_ECCKEY_BLOB priv_hdr{};
        priv_hdr.dwMagic = priv_magic;
        priv_hdr.cbKey = cb_key;
        copy_n(reinterpret_cast<unsigned char const *>(&priv_hdr),
               sizeof(priv_hdr),
               priv_blob.data());
        unsigned char *priv_ptr = priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        copy(x_bytes.begin(), x_bytes.end(), priv_ptr);
        copy(y_bytes.begin(), y_bytes.end(), priv_ptr + cb_key);
        copy(d_bytes.begin(), d_bytes.end(), priv_ptr + 2 * cb_key);
    }

    return make_unique<CNGECKey>(curve_name,
                                 x_bytes,
                                 y_bytes,
                                 d_bytes,
                                 std::move(pub_blob),
                                 std::move(priv_blob),
                                 key_guard.release(),
                                 alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateOct(unsigned int bits) const
{
    if (bits == 0 || bits % 8 != 0)
    {
        throw runtime_error("Key size must be a non-zero multiple of 8 bits");
    }

    vector<unsigned char> key_bytes(bits / 8);

    NTSTATUS const status = BCryptGenRandom(nullptr,
                                            key_bytes.data(),
                                            static_cast<ULONG>(key_bytes.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenRandom failed: " + getErrorString());
    }

    return make_unique<OctKey>(std::move(key_bytes));
}

unique_ptr<Key> CNGBackEnd::generateOct(unsigned int bits,
                                        vector<unsigned char> const &k_bytes) const
{
    auto const key_size(k_bytes.size());
    if (key_size != bits / 8)
    {
        throw runtime_error("Key size error");
    }

    return make_unique<OctKey>(std::move(k_bytes));
}

unique_ptr<Key> CNGBackEnd::generateOkp(Use use, unsigned int bits) const
{
    throw runtime_error("Not supported on Windows/CNG. Use an OpenSSL version.");
}

unique_ptr<Key> CNGBackEnd::generateOkp(string const &curve,
                                        vector<unsigned char> const &x_bytes,
                                        vector<unsigned char> const &d_bytes) const
{
    (void)curve;
    (void)x_bytes;
    (void)d_bytes;
    throw runtime_error("Not supported on Windows/CNG. Use an OpenSSL version.");
}

vector<unsigned char>
CNGBackEnd::sign_(SignatureAlgorithm algorithm, Key *key, std::span<unsigned char const> const &data) const
{
    if (key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    auto const hash_config(getSignatureHashConfig(algorithm));

    if (algorithm == SignatureAlgorithm::hs256 || algorithm == SignatureAlgorithm::hs384 ||
        algorithm == SignatureAlgorithm::hs512)
    {
        auto oct_key(dynamic_cast<OctKey *>(key));
        if (oct_key == nullptr)
        {
            throw runtime_error("HMAC signing requires an octet key");
        }

        auto const secret(oct_key->getK());
        if (secret.empty())
        {
            throw runtime_error("HMAC signing key material is empty");
        }
        if (secret.size() < static_cast<size_t>(hash_config.hash_size))
        {
            throw runtime_error("HMAC signing key material is too short for algorithm");
        }

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg,
                                                      hash_config.bcrypt_hash_name,
                                                      nullptr,
                                                      BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        ULONG hash_object_length(0);
        ULONG result_length(0);
        status = BCryptGetProperty(alg_guard.get(),
                                   BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&hash_object_length),
                                   sizeof(hash_object_length),
                                   &result_length,
                                   0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " +
                                getErrorString());
        }

        vector<unsigned char> hash_object(hash_object_length);
        BCRYPT_HASH_HANDLE h_hash(nullptr);
        status = BCryptCreateHash(alg_guard.get(),
                                  &h_hash,
                                  hash_object.empty() ? nullptr : hash_object.data(),
                                  static_cast<ULONG>(hash_object.size()),
                                  const_cast<PUCHAR>(secret.data()),
                                  static_cast<ULONG>(secret.size()),
                                  0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptCreateHash failed: " + getErrorString());
        }
        HashHandle hash_guard(h_hash);

        if (!data.empty())
        {
            status = BCryptHashData(h_hash,
                                    const_cast<PUCHAR>(data.data()),
                                    static_cast<ULONG>(data.size()),
                                    0);
            if (!BCRYPT_SUCCESS(status))
            {
                throw runtime_error("BCryptHashData failed: " + getErrorString());
            }
        }

        vector<unsigned char> signature(hash_config.hash_size);
        status =
            BCryptFinishHash(h_hash, signature.data(), static_cast<ULONG>(signature.size()), 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptFinishHash failed: " + getErrorString());
        }

        return signature;
    }

    vector<unsigned char> digest(this->hash(hash_config.hash_algorithm, data));

    if (isRsaPkcs1Algorithm(algorithm) || isRsaPssAlgorithm(algorithm))
    {
        auto rsa_key(dynamic_cast<RSAKey *>(key));
        if (rsa_key == nullptr)
        {
            throw runtime_error("RSA signing requires an RSA key");
        }

        vector<unsigned char> private_blob;
        auto cng_rsa_key(dynamic_cast<CNGRSAKey *>(key));
        if (cng_rsa_key != nullptr)
        {
            private_blob = cng_rsa_key->getPrivateBlob();
        }
        if (private_blob.empty())
        {
            private_blob = buildRsaFullPrivateBlob(*rsa_key);
        }

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_RSAFULLPRIVATE_BLOB,
                                     &h_key,
                                     private_blob.data(),
                                     static_cast<ULONG>(private_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        ULONG signature_size(0);
        ULONG consumed(0);
        ULONG flags(0);
        void *padding_info(nullptr);

        BCRYPT_PKCS1_PADDING_INFO pkcs1_padding_info{};
        BCRYPT_PSS_PADDING_INFO pss_padding_info{};
        if (isRsaPkcs1Algorithm(algorithm))
        {
            pkcs1_padding_info.pszAlgId = hash_config.bcrypt_hash_name;
            padding_info = &pkcs1_padding_info;
            flags = BCRYPT_PAD_PKCS1;
        }
        else
        {
            pss_padding_info.pszAlgId = hash_config.bcrypt_hash_name;
            pss_padding_info.cbSalt = hash_config.hash_size;
            padding_info = &pss_padding_info;
            flags = BCRYPT_PAD_PSS;
        }

        status = BCryptSignHash(key_guard.get(),
                                padding_info,
                                digest.empty() ? nullptr : digest.data(),
                                static_cast<ULONG>(digest.size()),
                                nullptr,
                                0,
                                &signature_size,
                                flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptSignHash(size query) failed: " + getErrorString());
        }

        vector<unsigned char> signature(signature_size);
        status = BCryptSignHash(key_guard.get(),
                                padding_info,
                                digest.empty() ? nullptr : digest.data(),
                                static_cast<ULONG>(digest.size()),
                                signature.data(),
                                static_cast<ULONG>(signature.size()),
                                &consumed,
                                flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptSignHash failed: " + getErrorString());
        }

        signature.resize(consumed);
        return signature;
    }

    if (isEcAlgorithm(algorithm))
    {
        auto ec_key(dynamic_cast<ECKey *>(key));
        if (ec_key == nullptr)
        {
            throw runtime_error("ECDSA signing requires an EC key");
        }

        wchar_t const *ec_alg_name(nullptr);
        ULONG ec_private_magic(0);
        ULONG ec_public_magic(0);
        resolveEcAlgorithm(algorithm, ec_alg_name, ec_private_magic, ec_public_magic);
        (void)ec_public_magic;

        vector<unsigned char> private_blob = buildEcPrivateBlob(*ec_key, ec_private_magic);

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, ec_alg_name, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_ECCPRIVATE_BLOB,
                                     &h_key,
                                     private_blob.data(),
                                     static_cast<ULONG>(private_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        ULONG signature_size(0);
        ULONG consumed(0);
        status = BCryptSignHash(key_guard.get(),
                                nullptr,
                                digest.empty() ? nullptr : digest.data(),
                                static_cast<ULONG>(digest.size()),
                                nullptr,
                                0,
                                &signature_size,
                                0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptSignHash(size query) failed: " + getErrorString());
        }

        vector<unsigned char> signature(signature_size);
        status = BCryptSignHash(key_guard.get(),
                                nullptr,
                                digest.empty() ? nullptr : digest.data(),
                                static_cast<ULONG>(digest.size()),
                                signature.data(),
                                static_cast<ULONG>(signature.size()),
                                &consumed,
                                0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptSignHash failed: " + getErrorString());
        }

        signature.resize(consumed);
        return signature;
    }

    throw runtime_error("Unsupported signature algorithm");
}

bool CNGBackEnd::verify_(SignatureAlgorithm algorithm,
                         Key *key,
                         std::vector<unsigned char> const &data,
                         std::vector<unsigned char> const &signature) const
{
    if (key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    auto const hash_config(getSignatureHashConfig(algorithm));

    if (algorithm == SignatureAlgorithm::hs256 || algorithm == SignatureAlgorithm::hs384 ||
        algorithm == SignatureAlgorithm::hs512)
    {
        vector<unsigned char> expected_signature(sign_(algorithm, key, data));
        if (expected_signature.size() != signature.size())
        {
            return false;
        }

        unsigned char diff = 0;
        for (size_t i = 0; i < expected_signature.size(); ++i)
        {
            diff |= static_cast<unsigned char>(expected_signature[i] ^ signature[i]);
        }
        return diff == 0;
    }

    vector<unsigned char> digest(this->hash(hash_config.hash_algorithm, data));

    if (isRsaPkcs1Algorithm(algorithm) || isRsaPssAlgorithm(algorithm))
    {
        auto rsa_key(dynamic_cast<RSAKey *>(key));
        if (rsa_key == nullptr)
        {
            throw runtime_error("RSA verification requires an RSA key");
        }

        vector<unsigned char> public_blob(buildRsaPublicBlob(*rsa_key));

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_RSAPUBLIC_BLOB,
                                     &h_key,
                                     public_blob.data(),
                                     static_cast<ULONG>(public_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        ULONG flags(0);
        void *padding_info(nullptr);
        BCRYPT_PKCS1_PADDING_INFO pkcs1_padding_info{};
        BCRYPT_PSS_PADDING_INFO pss_padding_info{};
        if (isRsaPkcs1Algorithm(algorithm))
        {
            pkcs1_padding_info.pszAlgId = hash_config.bcrypt_hash_name;
            padding_info = &pkcs1_padding_info;
            flags = BCRYPT_PAD_PKCS1;
        }
        else
        {
            pss_padding_info.pszAlgId = hash_config.bcrypt_hash_name;
            pss_padding_info.cbSalt = hash_config.hash_size;
            padding_info = &pss_padding_info;
            flags = BCRYPT_PAD_PSS;
        }

        status = BCryptVerifySignature(key_guard.get(),
                                       padding_info,
                                       digest.empty() ? nullptr : digest.data(),
                                       static_cast<ULONG>(digest.size()),
                                       const_cast<PUCHAR>(signature.data()),
                                       static_cast<ULONG>(signature.size()),
                                       flags);
        return BCRYPT_SUCCESS(status);
    }

    if (isEcAlgorithm(algorithm))
    {
        auto ec_key(dynamic_cast<ECKey *>(key));
        if (ec_key == nullptr)
        {
            throw runtime_error("ECDSA verification requires an EC key");
        }

        wchar_t const *ec_alg_name(nullptr);
        ULONG ec_private_magic(0);
        ULONG ec_public_magic(0);
        resolveEcAlgorithm(algorithm, ec_alg_name, ec_private_magic, ec_public_magic);
        (void)ec_private_magic;

        vector<unsigned char> public_blob(buildEcPublicBlob(*ec_key, ec_public_magic));

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, ec_alg_name, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_ECCPUBLIC_BLOB,
                                     &h_key,
                                     public_blob.data(),
                                     static_cast<ULONG>(public_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        status = BCryptVerifySignature(key_guard.get(),
                                       nullptr,
                                       digest.empty() ? nullptr : digest.data(),
                                       static_cast<ULONG>(digest.size()),
                                       const_cast<PUCHAR>(signature.data()),
                                       static_cast<ULONG>(signature.size()),
                                       0);
        return BCRYPT_SUCCESS(status);
    }

    throw runtime_error("Unsupported signature algorithm");
}

vector<unsigned char> CNGBackEnd::encryptKey_(KeyEncryptionAlgorithm algorithm,
                                              Key *key,
                                              vector<unsigned char> const &cek,
                                              optional<vector<unsigned char>> const &iv,
                                              optional<vector<unsigned char>> const &tag,
                                              Key *ephemeral_key,
                                              ContentEncryptionAlgorithm content_alg) const
{
    (void)iv;
    (void)tag;

    if (key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    if (algorithm == KeyEncryptionAlgorithm::dir)
    {
        return cek;
    }

    if (algorithm == KeyEncryptionAlgorithm::rsa1_5 ||
        algorithm == KeyEncryptionAlgorithm::rsa_oaep ||
        algorithm == KeyEncryptionAlgorithm::rsa_oaep_256)
    {
        auto rsa_key(dynamic_cast<RSAKey *>(key));
        if (rsa_key == nullptr)
        {
            throw runtime_error("RSA key encryption requires an RSA key");
        }

        vector<unsigned char> public_blob;
        auto cng_rsa_key(dynamic_cast<CNGRSAKey *>(key));
        if (cng_rsa_key != nullptr)
        {
            public_blob = cng_rsa_key->getPublicBlob();
        }
        if (public_blob.empty())
        {
            public_blob = buildRsaPublicBlob(*rsa_key);
        }

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_RSAPUBLIC_BLOB,
                                     &h_key,
                                     public_blob.data(),
                                     static_cast<ULONG>(public_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        ULONG encrypted_size(0);
        ULONG flags(0);
        void *padding_info(nullptr);
        BCRYPT_OAEP_PADDING_INFO oaep_padding_info{};

        if (algorithm == KeyEncryptionAlgorithm::rsa1_5)
        {
            flags = BCRYPT_PAD_PKCS1;
        }
        else
        {
            oaep_padding_info.pszAlgId = (algorithm == KeyEncryptionAlgorithm::rsa_oaep_256)
                                             ? BCRYPT_SHA256_ALGORITHM
                                             : BCRYPT_SHA1_ALGORITHM;
            oaep_padding_info.pbLabel = nullptr;
            oaep_padding_info.cbLabel = 0;
            padding_info = &oaep_padding_info;
            flags = BCRYPT_PAD_OAEP;
        }

        status = BCryptEncrypt(key_guard.get(),
                               cek.empty() ? nullptr : const_cast<PUCHAR>(cek.data()),
                               static_cast<ULONG>(cek.size()),
                               padding_info,
                               nullptr,
                               0,
                               nullptr,
                               0,
                               &encrypted_size,
                               flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptEncrypt(size query) failed: " + getErrorString());
        }

        vector<unsigned char> encrypted(encrypted_size);
        status = BCryptEncrypt(key_guard.get(),
                               cek.empty() ? nullptr : const_cast<PUCHAR>(cek.data()),
                               static_cast<ULONG>(cek.size()),
                               padding_info,
                               nullptr,
                               0,
                               encrypted.data(),
                               static_cast<ULONG>(encrypted.size()),
                               &encrypted_size,
                               flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptEncrypt failed: " + getErrorString());
        }

        encrypted.resize(encrypted_size);
        return encrypted;
    }

    if (algorithm == KeyEncryptionAlgorithm::a128kw ||
        algorithm == KeyEncryptionAlgorithm::a192kw || algorithm == KeyEncryptionAlgorithm::a256kw)
    {
        auto oct_key(dynamic_cast<OctKey *>(key));
        if (oct_key == nullptr)
        {
            throw runtime_error("AES key wrap requires an octet key");
        }

        vector<unsigned char> kek(oct_key->getK());
        size_t expected_kek_size = 0;
        if (algorithm == KeyEncryptionAlgorithm::a128kw)
        {
            expected_kek_size = 16;
        }
        else if (algorithm == KeyEncryptionAlgorithm::a192kw)
        {
            expected_kek_size = 24;
        }
        else
        {
            expected_kek_size = 32;
        }

        if (kek.size() != expected_kek_size)
        {
            throw runtime_error("AES key wrap key size does not match algorithm");
        }

        return aesKeyWrap(kek, cek);
    }

    if (algorithm == KeyEncryptionAlgorithm::ecdh_es)
    {
        auto ec_eph = dynamic_cast<ECKey *>(ephemeral_key);
        if (ec_eph == nullptr)
        {
            throw runtime_error("ECDH-ES requires an ephemeral EC key");
        }
        auto shared_secret = computeECDHSharedSecret(ec_eph, key);
        return concatKDF(shared_secret, cek.size(), JWA::toString(content_alg));
    }

    if (algorithm == KeyEncryptionAlgorithm::a128gcmkw ||
        algorithm == KeyEncryptionAlgorithm::a192gcmkw ||
        algorithm == KeyEncryptionAlgorithm::a256gcmkw)
    {
        auto oct_key = dynamic_cast<OctKey *>(key);
        if (oct_key == nullptr)
        {
            throw runtime_error("AES-GCM key wrap requires an octet key");
        }
        size_t expected_kek_size = (algorithm == KeyEncryptionAlgorithm::a128gcmkw)   ? 16
                                   : (algorithm == KeyEncryptionAlgorithm::a192gcmkw) ? 24
                                                                                      : 32;
        vector<unsigned char> kek = oct_key->getK();
        if (kek.size() != expected_kek_size)
        {
            throw runtime_error("AES-GCM key wrap key size does not match algorithm");
        }
        // Returns [IV(12)][ciphertext][tag(16)] — jwe.cpp splits these out.
        return aesGcmKeyWrapHelper(kek, cek);
    }

    throw runtime_error("Unsupported key encryption algorithm");
}

vector<unsigned char> CNGBackEnd::decryptKey_(KeyEncryptionAlgorithm algorithm,
                                              Key *key,
                                              vector<unsigned char> const &encrypted_cek,
                                              optional<vector<unsigned char>> const &iv,
                                              optional<vector<unsigned char>> const &tag,
                                              Key *ephemeral_key,
                                              ContentEncryptionAlgorithm content_alg) const
{
    if (key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    if (algorithm == KeyEncryptionAlgorithm::dir)
    {
        return encrypted_cek;
    }

    if (algorithm == KeyEncryptionAlgorithm::rsa1_5 ||
        algorithm == KeyEncryptionAlgorithm::rsa_oaep ||
        algorithm == KeyEncryptionAlgorithm::rsa_oaep_256)
    {
        auto rsa_key(dynamic_cast<RSAKey *>(key));
        if (rsa_key == nullptr)
        {
            throw runtime_error("RSA key decryption requires an RSA key");
        }

        vector<unsigned char> private_blob;
        auto cng_rsa_key(dynamic_cast<CNGRSAKey *>(key));
        if (cng_rsa_key != nullptr)
        {
            private_blob = cng_rsa_key->getPrivateBlob();
        }
        if (private_blob.empty())
        {
            private_blob = buildRsaFullPrivateBlob(*rsa_key);
        }

        BCRYPT_ALG_HANDLE h_alg(nullptr);
        NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
        }
        AlgHandle alg_guard(h_alg);

        BCRYPT_KEY_HANDLE h_key(nullptr);
        status = BCryptImportKeyPair(alg_guard.get(),
                                     nullptr,
                                     BCRYPT_RSAFULLPRIVATE_BLOB,
                                     &h_key,
                                     private_blob.data(),
                                     static_cast<ULONG>(private_blob.size()),
                                     0);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
        }
        KeyHandle key_guard(h_key);

        ULONG decrypted_size(0);
        ULONG flags(0);
        void *padding_info(nullptr);
        BCRYPT_OAEP_PADDING_INFO oaep_padding_info{};

        if (algorithm == KeyEncryptionAlgorithm::rsa1_5)
        {
            flags = BCRYPT_PAD_PKCS1;
        }
        else
        {
            oaep_padding_info.pszAlgId = (algorithm == KeyEncryptionAlgorithm::rsa_oaep_256)
                                             ? BCRYPT_SHA256_ALGORITHM
                                             : BCRYPT_SHA1_ALGORITHM;
            oaep_padding_info.pbLabel = nullptr;
            oaep_padding_info.cbLabel = 0;
            padding_info = &oaep_padding_info;
            flags = BCRYPT_PAD_OAEP;
        }

        status = BCryptDecrypt(key_guard.get(),
                               encrypted_cek.empty() ? nullptr
                                                     : const_cast<PUCHAR>(encrypted_cek.data()),
                               static_cast<ULONG>(encrypted_cek.size()),
                               padding_info,
                               nullptr,
                               0,
                               nullptr,
                               0,
                               &decrypted_size,
                               flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptDecrypt(size query) failed: " + getErrorString());
        }

        vector<unsigned char> decrypted(decrypted_size);
        status = BCryptDecrypt(key_guard.get(),
                               encrypted_cek.empty() ? nullptr
                                                     : const_cast<PUCHAR>(encrypted_cek.data()),
                               static_cast<ULONG>(encrypted_cek.size()),
                               padding_info,
                               nullptr,
                               0,
                               decrypted.data(),
                               static_cast<ULONG>(decrypted.size()),
                               &decrypted_size,
                               flags);
        if (!BCRYPT_SUCCESS(status))
        {
            throw runtime_error("BCryptDecrypt failed: " + getErrorString());
        }

        decrypted.resize(decrypted_size);
        return decrypted;
    }

    if (algorithm == KeyEncryptionAlgorithm::a128kw ||
        algorithm == KeyEncryptionAlgorithm::a192kw || algorithm == KeyEncryptionAlgorithm::a256kw)
    {
        auto oct_key(dynamic_cast<OctKey *>(key));
        if (oct_key == nullptr)
        {
            throw runtime_error("AES key unwrap requires an octet key");
        }

        vector<unsigned char> kek(oct_key->getK());
        size_t expected_kek_size = 0;
        if (algorithm == KeyEncryptionAlgorithm::a128kw)
        {
            expected_kek_size = 16;
        }
        else if (algorithm == KeyEncryptionAlgorithm::a192kw)
        {
            expected_kek_size = 24;
        }
        else
        {
            expected_kek_size = 32;
        }

        if (kek.size() != expected_kek_size)
        {
            throw runtime_error("AES key unwrap key size does not match algorithm");
        }

        return aesKeyUnwrap(kek, encrypted_cek);
    }

    if (algorithm == KeyEncryptionAlgorithm::ecdh_es)
    {
        auto ec_key = dynamic_cast<ECKey *>(key);
        auto ec_eph = dynamic_cast<ECKey *>(ephemeral_key);
        if (ec_key == nullptr || ec_eph == nullptr)
        {
            throw runtime_error("ECDH-ES key agreement requires EC keys");
        }
        // shared secret: recipient_private × ephemeral_public
        auto shared_secret = computeECDHSharedSecret(key, ephemeral_key);

        // Derive the CEK — its length depends on the content algorithm.
        size_t derived_key_len = 0;
        switch (content_alg)
        {
            case ContentEncryptionAlgorithm::a128gcm:
                derived_key_len = 16;
                break;
            case ContentEncryptionAlgorithm::a128cbc_hs256:
                derived_key_len = 32;  // 16 (HMAC-SHA-256) + 16 (AES-128)
                break;
            case ContentEncryptionAlgorithm::a192gcm:
                derived_key_len = 24;
                break;
            case ContentEncryptionAlgorithm::a192cbc_hs384:
                derived_key_len = 48;  // 24 (HMAC-SHA-384) + 24 (AES-192)
                break;
            case ContentEncryptionAlgorithm::a256gcm:
                derived_key_len = 32;
                break;
            case ContentEncryptionAlgorithm::a256cbc_hs512:
                derived_key_len = 64;  // 32 (HMAC-SHA-512) + 32 (AES-256)
                break;
            default:
                throw runtime_error("Unsupported content algorithm for ECDH-ES");
        }
        return concatKDF(shared_secret, derived_key_len, JWA::toString(content_alg));
    }

    if (algorithm == KeyEncryptionAlgorithm::a128gcmkw ||
        algorithm == KeyEncryptionAlgorithm::a192gcmkw ||
        algorithm == KeyEncryptionAlgorithm::a256gcmkw)
    {
        auto oct_key = dynamic_cast<OctKey *>(key);
        if (oct_key == nullptr)
        {
            throw runtime_error("AES-GCM key unwrap requires an octet key");
        }
        size_t expected_kek_size = (algorithm == KeyEncryptionAlgorithm::a128gcmkw)   ? 16
                                   : (algorithm == KeyEncryptionAlgorithm::a192gcmkw) ? 24
                                                                                      : 32;
        vector<unsigned char> kek = oct_key->getK();
        if (kek.size() != expected_kek_size)
        {
            throw runtime_error("AES-GCM key unwrap key size does not match algorithm");
        }
        return aesGcmKeyUnwrapHelper(kek, encrypted_cek, iv, tag);
    }

    throw runtime_error("Unsupported key encryption algorithm");
}

pair<vector<unsigned char>, vector<unsigned char>>
CNGBackEnd::encryptContent_(ContentEncryptionAlgorithm algorithm,
                            vector<unsigned char> const &cek,
                            vector<unsigned char> const &iv,
                            vector<unsigned char> const &plaintext,
                            vector<unsigned char> const &aad) const
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128gcm:
            if (cek.size() != 16)
            {
                throw runtime_error("A128GCM requires a 128-bit CEK");
            }
            return aesGcmEncrypt(cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a192gcm:
            if (cek.size() != 24)
            {
                throw runtime_error("A192GCM requires a 192-bit CEK");
            }
            return aesGcmEncrypt(cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a256gcm:
            if (cek.size() != 32)
            {
                throw runtime_error("A256GCM requires a 256-bit CEK");
            }
            return aesGcmEncrypt(cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacEncrypt(16, 16, BCRYPT_SHA256_ALGORITHM, 16, cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacEncrypt(24, 24, BCRYPT_SHA384_ALGORITHM, 24, cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacEncrypt(32, 32, BCRYPT_SHA512_ALGORITHM, 32, cek, iv, plaintext, aad);
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

vector<unsigned char> CNGBackEnd::decryptContent_(ContentEncryptionAlgorithm algorithm,
                                                  vector<unsigned char> const &cek,
                                                  vector<unsigned char> const &iv,
                                                  vector<unsigned char> const &ciphertext,
                                                  vector<unsigned char> const &aad,
                                                  vector<unsigned char> const &tag) const
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128gcm:
            if (cek.size() != 16)
            {
                throw runtime_error("A128GCM requires a 128-bit CEK");
            }
            return aesGcmDecrypt(cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a192gcm:
            if (cek.size() != 24)
            {
                throw runtime_error("A192GCM requires a 192-bit CEK");
            }
            return aesGcmDecrypt(cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a256gcm:
            if (cek.size() != 32)
            {
                throw runtime_error("A256GCM requires a 256-bit CEK");
            }
            return aesGcmDecrypt(cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacDecrypt(16,
                                     16,
                                     BCRYPT_SHA256_ALGORITHM,
                                     16,
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);
        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacDecrypt(24,
                                     24,
                                     BCRYPT_SHA384_ALGORITHM,
                                     24,
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);
        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacDecrypt(32,
                                     32,
                                     BCRYPT_SHA512_ALGORITHM,
                                     32,
                                     cek,
                                     iv,
                                     ciphertext,
                                     aad,
                                     tag);
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

vector<unsigned char> CNGBackEnd::hash(HashAlgorithm algorithm,
                                       vector<unsigned char> const &data) const
{
    wchar_t const *algorithm_name(nullptr);
    switch (algorithm)
    {
        case HashAlgorithm::sha256:
            algorithm_name = BCRYPT_SHA256_ALGORITHM;
            break;
        case HashAlgorithm::sha384:
            algorithm_name = BCRYPT_SHA384_ALGORITHM;
            break;
        case HashAlgorithm::sha512:
            algorithm_name = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            throw runtime_error("Unsupported hash algorithm");
    }

    BCRYPT_ALG_HANDLE h_alg(nullptr);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, algorithm_name, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(h_alg);

    ULONG hash_object_length(0);
    ULONG result_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_object_length),
                               sizeof(hash_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + getErrorString());
    }

    ULONG hash_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_length),
                               sizeof(hash_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed: " + getErrorString());
    }

    vector<unsigned char> hash_object(hash_object_length);
    BCRYPT_HASH_HANDLE h_hash(nullptr);
    status = BCryptCreateHash(alg_guard.get(),
                              &h_hash,
                              hash_object.empty() ? nullptr : hash_object.data(),
                              static_cast<ULONG>(hash_object.size()),
                              nullptr,
                              0,
                              0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptCreateHash failed: " + getErrorString());
    }

    if (!data.empty())
    {
        status = BCryptHashData(h_hash,
                                const_cast<PUCHAR>(data.data()),
                                static_cast<ULONG>(data.size()),
                                0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptDestroyHash(h_hash);
            throw runtime_error("BCryptHashData failed: " + getErrorString());
        }
    }

    vector<unsigned char> digest(hash_length);
    status = BCryptFinishHash(h_hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(h_hash);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinishHash failed: " + getErrorString());
    }

    return digest;
}
//
// vector<unsigned char> CNGBackEnd::derive(JWK const& private_key,
//                                          JWK const& peer_key) const
//{
//    throw logic_error("Not yet implemented");
//    return {};
//}
//
// vector<unsigned char> CNGBackEnd::randomBytes(size_t size) const
//{
//    throw logic_error("Not yet implemented");
//    return {};
//}

string CNGBackEnd::getErrorString() const
{
    DWORD err = ::GetLastError();
    if (err == 0)
    {
        return string();
    }

    LPSTR msg_buf = nullptr;
    DWORD size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                    FORMAT_MESSAGE_IGNORE_INSERTS,
                                nullptr,
                                err,
                                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                reinterpret_cast<LPSTR>(&msg_buf),
                                0,
                                nullptr);

    string msg;
    if (size && msg_buf)
    {
        msg.assign(msg_buf, size);
        LocalFree(msg_buf);
    }
    else
    {
        msg = string("Unknown error ") + to_string(err);
    }

    return msg;
}

///// Get hash algorithm for signature
// void const*
// CNGBackEnd::getHashAlgorithm(SignatureAlgorithm signature_algorithm) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }

}  // namespace Private

}  // namespace JOSE
}  // namespace Vlinder
