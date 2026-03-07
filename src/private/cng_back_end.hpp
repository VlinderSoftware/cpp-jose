#define WIN32_NO_STATUS
#include <windows.h>
#include <bcrypt.h>

#include "back_end.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

/// RAII guards for CNG opaque handles (both typedef PVOID).
/// Stateless lambdas are default-constructible in C++20, so they work
/// directly as unique_ptr deleters without a named functor struct.
using AlgHandle = std::unique_ptr<void, decltype([](void *h) noexcept { BCryptCloseAlgorithmProvider(h, 0); })>;
using KeyHandle = std::unique_ptr<void, decltype([](void *h) noexcept { BCryptDestroyKey(h); })>;

class CNGRSAKey : public RSAKey
{
public:
    CNGRSAKey(std::vector<unsigned char> n,
              std::vector<unsigned char> e,
              std::vector<unsigned char> d,
              std::vector<unsigned char> p,
              std::vector<unsigned char> q,
              std::vector<unsigned char> dp,
              std::vector<unsigned char> dq,
              std::vector<unsigned char> iqmp,
              std::vector<unsigned char> public_blob,
              std::vector<unsigned char> private_blob,
              BCRYPT_KEY_HANDLE key_handle = nullptr,
              BCRYPT_ALG_HANDLE alg_handle = nullptr);
    ~CNGRSAKey() override = default;

    std::vector<unsigned char> getPublicBlob() const;
    std::vector<unsigned char> getPrivateBlob() const;
    bool hasPrivate() const override;

    std::unique_ptr<Private::Key> clone() const override;
    std::vector<unsigned char> getN() const override;
    std::vector<unsigned char> getE() const override;
    std::vector<unsigned char> getD() const override;
    std::vector<unsigned char> getP() const override;
    std::vector<unsigned char> getQ() const override;
    std::vector<unsigned char> getDp() const override;
    std::vector<unsigned char> getDq() const override;
    std::vector<unsigned char> getQi() const override;

private:
    std::vector<unsigned char> public_blob_;
    std::vector<unsigned char> private_blob_;
    // Parsed RSA parameters
    std::vector<unsigned char> n_;
    std::vector<unsigned char> e_;
    std::vector<unsigned char> d_;
    std::vector<unsigned char> p_;
    std::vector<unsigned char> q_;
    std::vector<unsigned char> dp_;
    std::vector<unsigned char> dq_;
    std::vector<unsigned char> iqmp_;
    KeyHandle key_handle_;
    AlgHandle alg_handle_;
};

class CNGECKey : public ECKey
{
public:
    CNGECKey(std::string curve_name,
             std::vector<unsigned char> const &x,
             std::vector<unsigned char> const &y,
             std::vector<unsigned char> const &d,
             std::vector<unsigned char> public_blob,
             std::vector<unsigned char> private_blob = {},
             BCRYPT_KEY_HANDLE key_handle = nullptr,
             BCRYPT_ALG_HANDLE alg_handle = nullptr);
    ~CNGECKey() override = default;

    std::vector<unsigned char> getPublicBlob() const override;
    std::vector<unsigned char> getPrivateBlob() const override;
    bool hasPrivate() const override;
    std::unique_ptr<Private::Key> clone() const override;
    virtual std::vector<unsigned char> getX() const override
    {
        return x_;
    }
    virtual std::vector<unsigned char> getY() const override
    {
        return y_;
    }
    virtual std::vector<unsigned char> getD() const override
    {
        return d_;
    }

private:
    std::vector<unsigned char> x_;
    std::vector<unsigned char> y_;
    std::vector<unsigned char> d_;
    std::vector<unsigned char> public_blob_;
    std::vector<unsigned char> private_blob_;
    KeyHandle key_handle_;
    AlgHandle alg_handle_;
};

class CNGBackEnd : public BackEnd
{
public:
    virtual std::unique_ptr<Key> generateRSA(unsigned int bits) const override;
    virtual std::unique_ptr<Key>
    generateRSA(std::vector<unsigned char> const &n_bytes,
                std::vector<unsigned char> const &e_bytes,
                std::vector<unsigned char> const &d_bytes,
                std::vector<unsigned char> const &p_bytes,
                std::vector<unsigned char> const &q_bytes,
                std::vector<unsigned char> const &dp_bytes,
                std::vector<unsigned char> const &dq_bytes,
                std::vector<unsigned char> const &qi_bytes) const override;
    virtual std::unique_ptr<Key> generateEC(std::string const &curve) const override;
    virtual std::unique_ptr<Key>
    generateEC(std::string const &curve,
               std::vector<unsigned char> const &x_bytes,
               std::vector<unsigned char> const &y_bytes,
               std::vector<unsigned char> const &d_bytes) const override;
    virtual std::unique_ptr<Key> generateOct(unsigned int bits) const override;
    virtual std::unique_ptr<Key>
    generateOct(unsigned int bits, std::vector<unsigned char> const &k_bytes) const override;
    virtual std::unique_ptr<Key> generateOkp(Use use, unsigned int bits) const override;
    virtual std::unique_ptr<Key>
    generateOkp(std::string const &curve,
                std::vector<unsigned char> const &x_bytes,
                std::vector<unsigned char> const &d_bytes) const override;

    // virtual std::vector<unsigned char> sign(SignatureAlgorithm algorithm, JWK const& key,
    //                                         std::vector<unsigned char> const& data) const
    //                                         override;

    // virtual bool verify(SignatureAlgorithm algorithm, JWK const& key,
    //                     std::vector<unsigned char> const& data,
    //                     std::vector<unsigned char> const& signature) const override;

    // virtual std::vector<unsigned char>
    // encrypt(ContentEncryptionAlgorithm algorithm, JWK const& key,
    //         std::vector<unsigned char> const& plaintext) const override;

    // virtual std::vector<unsigned char>
    // decrypt(ContentEncryptionAlgorithm algorithm, JWK const& key,
    //         std::vector<unsigned char> const& ciphertext) const override;

    virtual std::vector<unsigned char> hash(HashAlgorithm algorithm,
                                            std::vector<unsigned char> const &data) const override;

    // virtual std::vector<unsigned char> derive(JWK const& private_key,
    //                                           JWK const& peer_key) const override;

    // virtual std::vector<unsigned char> randomBytes(size_t size) const override;

    /// Base64 encode
    virtual std::string base64Encode(std::vector<unsigned char> const &data) const override;
    /// Base64 decode
    virtual std::vector<unsigned char> base64Decode(std::string const &encoded) const override;

    /// Backend-specific error string
    virtual std::string getErrorString() const override;

    ///// Get hash algorithm for signature
    // virtual void const* getHashAlgorithm(SignatureAlgorithm signature_algorithm) const override;
};

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
