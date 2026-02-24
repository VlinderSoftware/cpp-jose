#include "details/crypto_backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Details {

class CNGBackend : public CryptoBackend
{
public:
    std::vector<unsigned char> sign(SignatureAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &data) override
    {
        // TODO: Implement CNG sign
        return {};
    }
    bool verify(SignatureAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &data, std::vector<unsigned char> const &signature) override
    {
        // TODO: Implement CNG verify
        return false;
    }
    std::vector<unsigned char> encrypt(EncryptionAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &plaintext) override
    {
        // TODO: Implement CNG encrypt
        return {};
    }
    std::vector<unsigned char> decrypt(EncryptionAlgorithm algorithm, CryptoKey const &key, std::vector<unsigned char> const &ciphertext) override
    {
        // TODO: Implement CNG decrypt
        return {};
    }
    std::vector<unsigned char> hash(HashAlgorithm algorithm, std::vector<unsigned char> const &data) override
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
