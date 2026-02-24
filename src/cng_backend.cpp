#include "details/crypto_backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Details {

class CNGBackend : public CryptoBackend
{
public:
    std::vector<unsigned char> sign(SignatureAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &data) override
    {
        // TODO: Implement CNG sign
        return {};
    }
    bool verify(SignatureAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &data, const std::vector<unsigned char> &signature) override
    {
        // TODO: Implement CNG verify
        return false;
    }
    std::vector<unsigned char> encrypt(EncryptionAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &plaintext) override
    {
        // TODO: Implement CNG encrypt
        return {};
    }
    std::vector<unsigned char> decrypt(EncryptionAlgorithm algorithm, const CryptoKey &key, const std::vector<unsigned char> &ciphertext) override
    {
        // TODO: Implement CNG decrypt
        return {};
    }
    std::vector<unsigned char> hash(HashAlgorithm algorithm, const std::vector<unsigned char> &data) override
    {
        // TODO: Implement CNG hash
        return {};
    }
    std::vector<unsigned char> randomBytes(size_t size) override
    {
        // TODO: Implement CNG randomBytes
        return {};
    }
};

} // namespace Details
} // namespace JOSE
} // namespace Vlinder
