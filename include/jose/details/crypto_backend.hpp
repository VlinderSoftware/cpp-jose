#pragma once

#include <vector>
#include <string>
#include <memory>

namespace Vlinder {
namespace JOSE {
namespace Details {

/// Enum for signature algorithms
enum class SignatureAlgorithm
{
    hs256,
    hs384,
    hs512,
    rs256,
    rs384,
    rs512,
    es256,
    es384,
    es512,
    ps256,
    ps384,
    ps512,
    none
};

/// Enum for encryption algorithms
enum class EncryptionAlgorithm
{
    rsa1_5,
    rsa_oaep,
    rsa_oaep_256,
    a128kw,
    a192kw,
    a256kw,
    dir,
    ecdh_es,
    a128gcmkw,
    a192gcmkw,
    a256gcmkw
};

/// Enum for hash algorithms
enum class HashAlgorithm
{
    sha256,
    sha384,
    sha512
};

/// Strongly-typed key abstraction
class CryptoKey
{
public:
    virtual ~CryptoKey() = default;
};

class CryptoBackend
{
public:
    virtual ~CryptoBackend() = default;

    virtual std::vector<unsigned char> sign(
        SignatureAlgorithm algorithm,
        CryptoKey const &key,
        std::vector<unsigned char> const &data) = 0;

    virtual bool verify(
        SignatureAlgorithm algorithm,
        CryptoKey const &key,
        std::vector<unsigned char> const &data,
        std::vector<unsigned char> const &signature) = 0;

    virtual std::vector<unsigned char> encrypt(
        EncryptionAlgorithm algorithm,
        CryptoKey const &key,
        std::vector<unsigned char> const &plaintext) = 0;

    virtual std::vector<unsigned char> decrypt(
        EncryptionAlgorithm algorithm,
        CryptoKey const &key,
        std::vector<unsigned char> const &ciphertext) = 0;

    virtual std::vector<unsigned char> hash(
        HashAlgorithm algorithm,
        std::vector<unsigned char> const &data) = 0;

    virtual std::vector<unsigned char> randomBytes(size_t size) = 0;
};

} // namespace Details
} // namespace JOSE
} // namespace Vlinder
