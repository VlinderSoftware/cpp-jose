#include "details/crypto_backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Details {

class OpenSSLBackend : public CryptoBackend
{
public:
    std::vector<unsigned char> sign(SignatureAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &data) override
    {
        // TODO: Implement OpenSSL sign
        return {};
    }
    bool verify(SignatureAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &data, std::vector<unsigned char> const &signature) override
    {
        // TODO: Implement OpenSSL verify
        return false;
    }
    std::vector<unsigned char> encrypt(EncryptionAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &plaintext) override
    {
        // TODO: Implement OpenSSL encrypt
        return {};
    }
    std::vector<unsigned char> decrypt(EncryptionAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &ciphertext) override
    {
        // TODO: Implement OpenSSL decrypt
        return {};
    }
    std::vector<unsigned char> hash(HashAlgorithm algorithm, std::vector<unsigned char> const &data) override
    {
        // TODO: Implement OpenSSL hash
        return {};
    }
    std::vector<unsigned char> randomBytes(size_t size) override
    {
        // TODO: Implement OpenSSL randomBytes
        return {};
    }
};

} // namespace Details
} // namespace JOSE
} // namespace Vlinder
