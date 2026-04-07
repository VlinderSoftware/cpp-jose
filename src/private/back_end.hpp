#pragma once

#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "jwa.hpp"
#include "jwk.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

typedef JWK::KeyType KeyType;
typedef JWA::SignatureAlgorithm SignatureAlgorithm;
typedef JWA::KeyEncryptionAlgorithm KeyEncryptionAlgorithm;
typedef JWA::ContentEncryptionAlgorithm ContentEncryptionAlgorithm;
typedef JWK::Use Use;
enum class HashAlgorithm
{
    sha256,
    sha384,
    sha512
};

class Key
{
public:
    KeyType getKeyType() const
    {
        return key_type_;
    }

    virtual ~Key() = default;

    /// Whether private material is present
    virtual bool hasPrivate() const = 0;

    /// Return a deep copy of this key. CNG/OpenSSL handles are not duplicated;
    /// the clone carries only the serialisable key material.
    virtual std::unique_ptr<Key> clone() const = 0;

protected:
    Key(KeyType key_type) : key_type_(key_type)
    {
    }

private:
    KeyType key_type_;
};

// Abstract key wrapper used by backends. Concrete backends should derive
// from this to store backend-specific key material.
class AsymmetricKey : public Key
{
public:
    virtual ~AsymmetricKey() = default;

    /// Return public key material (backend-specific blob)
    virtual std::vector<unsigned char> getPublicBlob() const = 0;

    /// Return private key material (backend-specific blob); may be empty
    virtual std::vector<unsigned char> getPrivateBlob() const = 0;

protected:
    AsymmetricKey(KeyType key_type) : Key(key_type)
    {
    }
};

class RSAKey : public AsymmetricKey
{
public:
    RSAKey() : AsymmetricKey(KeyType::rsa)
    {
    }

    // RSA parameter accessors
    virtual std::vector<unsigned char> getN() const = 0;
    virtual std::vector<unsigned char> getE() const = 0;
    virtual std::vector<unsigned char> getD() const = 0;
    virtual std::vector<unsigned char> getP() const = 0;
    virtual std::vector<unsigned char> getQ() const = 0;
    virtual std::vector<unsigned char> getDp() const = 0;
    virtual std::vector<unsigned char> getDq() const = 0;
    virtual std::vector<unsigned char> getQi() const = 0;
};

class ECKey : public AsymmetricKey
{
public:
    ECKey(std::string const &curve_name) : AsymmetricKey(KeyType::ec), curve_name_(curve_name)
    {
    }

    std::string getCurveName() const
    {
        return curve_name_;
    }

    virtual std::vector<unsigned char> getX() const = 0;
    virtual std::vector<unsigned char> getY() const = 0;
    virtual std::vector<unsigned char> getD() const = 0;

private:
    std::string curve_name_;
};

class OKPKey : public AsymmetricKey
{
public:
    OKPKey(std::string const &curve_name) : AsymmetricKey(KeyType::okp), curve_name_(curve_name)
    {
    }

    std::string getCurveName() const
    {
        return curve_name_;
    }

    virtual std::vector<unsigned char> getX() const = 0;
    virtual std::vector<unsigned char> getD() const = 0;

private:
    std::string curve_name_;
};

class OctKey : public Key
{
public:
    OctKey(std::vector<unsigned char> const &k = {}) : Key(KeyType::oct), k_(k)
    {
    }

    std::vector<unsigned char> getK() const
    {
        return k_;
    }

    virtual bool hasPrivate() const override
    {
        return !k_.empty();
    }

    std::unique_ptr<Key> clone() const override
    {
        return std::make_unique<OctKey>(k_);
    }

private:
    std::vector<unsigned char> k_;
};

class BackEnd
{
public:
    virtual ~BackEnd() = default;

    std::vector<unsigned char> concatKDF(std::vector<unsigned char> const &shared_secret,
                                         size_t key_data_len,
                                         std::string const &algorithm,
                                         std::vector<unsigned char> const &apu = {},
                                         std::vector<unsigned char> const &apv = {}) const;

    virtual std::unique_ptr<Key> generateRSA(unsigned int bits) const = 0;
    virtual std::unique_ptr<Key> generateRSA(std::vector<unsigned char> const &n_bytes,
                                             std::vector<unsigned char> const &e_bytes,
                                             std::vector<unsigned char> const &d_bytes,
                                             std::vector<unsigned char> const &p_bytes,
                                             std::vector<unsigned char> const &q_bytes,
                                             std::vector<unsigned char> const &dp_bytes,
                                             std::vector<unsigned char> const &dq_bytes,
                                             std::vector<unsigned char> const &qi_bytes) const = 0;
    virtual std::unique_ptr<Key> generateEC(std::string const &curve) const = 0;
    virtual std::unique_ptr<Key> generateEC(std::string const &curve,
                                            std::vector<unsigned char> const &x_bytes,
                                            std::vector<unsigned char> const &y_bytes,
                                            std::vector<unsigned char> const &d_bytes) const = 0;
    virtual std::unique_ptr<Key> generateOct(unsigned int bits) const = 0;
    virtual std::unique_ptr<Key> generateOct(unsigned int bits,
                                             std::vector<unsigned char> const &k_bytes) const = 0;
    virtual std::unique_ptr<Key> generateOkp(Use use, unsigned int bits) const = 0;
    virtual std::unique_ptr<Key> generateOkp(std::string const &curve,
                                             std::vector<unsigned char> const &x_bytes,
                                             std::vector<unsigned char> const &d_bytes) const = 0;

    std::vector<unsigned char> sign(SignatureAlgorithm algorithm,
                                    JWK const &key,
                                    std::vector<unsigned char> const &data) const;

    std::vector<unsigned char> sign(SignatureAlgorithm algorithm,
                                    JWK const &key,
                                    std::span<unsigned char const> const &data) const;

    bool verify(SignatureAlgorithm algorithm,
                JWK const &key,
                std::vector<unsigned char> const &data,
                std::vector<unsigned char> const &signature) const;

    std::vector<unsigned char> encryptKey(KeyEncryptionAlgorithm algorithm,
                                          const JWK &key,
                                          std::vector<unsigned char> const &cek,
                                          std::optional<std::vector<unsigned char>> const &iv,
                                          std::optional<std::vector<unsigned char>> const &tag,
                                          std::optional<JWK> const &ephemeral_key,
                                          ContentEncryptionAlgorithm content_alg) const;

    std::vector<unsigned char>
    decryptKey(KeyEncryptionAlgorithm algorithm,
               JWK const &key,
               std::vector<unsigned char> const &encrypted_cek,
               std::optional<std::vector<unsigned char>> const &iv = {},
               std::optional<std::vector<unsigned char>> const &tag = {},
               std::optional<JWK> const &ephemeral_key = {},
               ContentEncryptionAlgorithm content_alg = ContentEncryptionAlgorithm::a128gcm) const;

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
    encryptContent(ContentEncryptionAlgorithm algorithm,
                   std::vector<unsigned char> const &cek,
                   std::vector<unsigned char> const &iv,
                   std::vector<unsigned char> const &plaintext,
                   std::vector<unsigned char> const &aad) const;

    std::vector<unsigned char> decryptContent(ContentEncryptionAlgorithm algorithm,
                                              std::vector<unsigned char> const &cek,
                                              std::vector<unsigned char> const &iv,
                                              std::vector<unsigned char> const &ciphertext,
                                              std::vector<unsigned char> const &aad,
                                              std::vector<unsigned char> const &tag) const;

    std::vector<unsigned char> hash(HashAlgorithm algorithm,
                                    std::vector<unsigned char> const &data) const
    {
        return hash(algorithm, std::span<unsigned char const>{data});
    }
    virtual std::vector<unsigned char> hash(HashAlgorithm algorithm,
                                            std::span<unsigned char const> const &data) const = 0;

    /// Returns a backend-specific error string (stub for non-OpenSSL backends)
    virtual std::string getErrorString() const
    {
        return "";
    }

    /// Base64 encode (standard alphabet, no line breaks, with padding)
    std::string base64Encode(std::vector<unsigned char> const &data) const;
    /// Base64 encode (standard alphabet, no line breaks, with padding)
    std::string base64Encode(std::span<unsigned char const> const &data) const;
    /// Base64 decode (standard or URL-safe alphabet, optional padding)
    std::vector<unsigned char> base64Decode(std::string const &encoded) const;

    ///// Get hash algorithm for signature
    // virtual void const *getHashAlgorithm(SignatureAlgorithm signature_algorithm) const = 0;
protected:
    virtual std::vector<unsigned char> sign_(SignatureAlgorithm algorithm,
                                             Key *key,
                                             std::span<unsigned char const> const &data) const = 0;
    virtual bool verify_(SignatureAlgorithm algorithm,
                         Key *key,
                         std::vector<unsigned char> const &data,
                         std::vector<unsigned char> const &signature) const = 0;
    virtual std::vector<unsigned char>
    encryptKey_(KeyEncryptionAlgorithm algorithm,
                Key *key,
                std::vector<unsigned char> const &cek,
                std::optional<std::vector<unsigned char>> const &iv,
                std::optional<std::vector<unsigned char>> const &tag,
                Key *ephemeral_key,
                ContentEncryptionAlgorithm content_alg) const = 0;
    virtual std::vector<unsigned char>
    decryptKey_(KeyEncryptionAlgorithm algorithm,
                Key *key,
                std::vector<unsigned char> const &encrypted_cek,
                std::optional<std::vector<unsigned char>> const &iv,
                std::optional<std::vector<unsigned char>> const &tag,
                Key *ephemeral_key,
                ContentEncryptionAlgorithm content_alg) const = 0;
    virtual std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
    encryptContent_(ContentEncryptionAlgorithm algorithm,
                    std::vector<unsigned char> const &cek,
                    std::vector<unsigned char> const &iv,
                    std::vector<unsigned char> const &plaintext,
                    std::vector<unsigned char> const &aad) const = 0;
    virtual std::vector<unsigned char>
    decryptContent_(ContentEncryptionAlgorithm algorithm,
                    std::vector<unsigned char> const &cek,
                    std::vector<unsigned char> const &iv,
                    std::vector<unsigned char> const &ciphertext,
                    std::vector<unsigned char> const &aad,
                    std::vector<unsigned char> const &tag) const = 0;
};

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
