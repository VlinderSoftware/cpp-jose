#include "details/crypto_backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Details {

class OpenSSLBackend : public CryptoBackend
{
public:
    std::vector<unsigned char> sign(SignatureAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &data) override
    {
        // TODO: Implement OpenSSL sign
        return {};
    }
    bool verify(SignatureAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &data, const std::vector<unsigned char> &signature) override
    {
        // TODO: Implement OpenSSL verify
        return false;
    }
    std::vector<unsigned char> encrypt(EncryptionAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &plaintext) override
    {
        // TODO: Implement OpenSSL encrypt
        return {};
    }
    std::vector<unsigned char> decrypt(EncryptionAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &ciphertext) override
    {
        // TODO: Implement OpenSSL decrypt
        return {};
    }
    std::vector<unsigned char> hash(HashAlgorithm algorithm, const std::vector<unsigned char> &data) override
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
