#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "details/backend.hpp"

namespace Vlinder {
namespace JOSE {
namespace Details {

class OpenSSLBackend : public Backend
{
public:
#if 0
    // Use OpenSSL to do base64 encoding
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
#endif

#if 0
    // Decode using OpenSSL
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> result(base64.length());
    int decoded_length = BIO_read(bio, result.data(), static_cast<int>(result.size()));

    BIO_free_all(bio);

    if (decoded_length < 0)
    {
        throw std::runtime_error("Failed to decode base64url");
    }

    result.resize(decoded_length);
    return result;
#endif

    std::vector<unsigned char> sign(SignatureAlgorithm algorithm, KeyRing const& key,
                                    std::vector<unsigned char> const& data) const override
    {
        // TODO: Implement OpenSSL sign
        return {};
    }
    bool verify(SignatureAlgorithm algorithm, KeyRing const& key,
                std::vector<unsigned char> const& data,
                std::vector<unsigned char> const& signature) const override
    {
        // TODO: Implement OpenSSL verify
        return false;
    }
    std::vector<unsigned char> encrypt(EncryptionAlgorithm algorithm, KeyRing const& key,
                                       std::vector<unsigned char> const& plaintext) const override
    {
        // TODO: Implement OpenSSL encrypt
        return {};
    }
    std::vector<unsigned char> decrypt(EncryptionAlgorithm algorithm, KeyRing const& key,
                                       std::vector<unsigned char> const& ciphertext) const override
    {
        // TODO: Implement OpenSSL decrypt
        return {};
    }
    std::vector<unsigned char> hash(HashAlgorithm algorithm,
                                    std::vector<unsigned char> const& data) const override
    {
        // TODO: Implement OpenSSL hash
        return {};
    }
    std::vector<unsigned char> randomBytes(size_t size) const override
    {
        // TODO: Implement OpenSSL randomBytes
        return {};
    }
    std::string getErrorString() const override
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
};

}  // namespace Details
}  // namespace JOSE
}  // namespace Vlinder
