#include <catch2/catch_test_macros.hpp>

#include "../src/private/back_end.hpp"

using namespace std;

using namespace Vlinder::JOSE::Private;

// Minimal test backend that provides a deterministic "hash" implementation
// returning 32 bytes of 0xAA for any input. This lets concatKDF behavior be
// predicted without depending on OpenSSL/CNG.
class TestBackEnd : public BackEnd
{
public:
    Result<vector<unsigned char>> hash(HashAlgorithm /*algorithm*/,
                                       span<unsigned char const> const & /*data*/) const override
    {
        return makeOk<vector<unsigned char>>(vector<unsigned char>(32, 0xAA));
    }

    Result<unique_ptr<Key>> generateRSA(unsigned int bits) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateRSA(vector<unsigned char> const &n_bytes,
                                        vector<unsigned char> const &e_bytes,
                                        vector<unsigned char> const &d_bytes,
                                        vector<unsigned char> const &p_bytes,
                                        vector<unsigned char> const &q_bytes,
                                        vector<unsigned char> const &dp_bytes,
                                        vector<unsigned char> const &dq_bytes,
                                        vector<unsigned char> const &qi_bytes) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateEC(string const &) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateEC(string const &,
                                       vector<unsigned char> const &,
                                       vector<unsigned char> const &,
                                       vector<unsigned char> const &) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateOct(unsigned int bits) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateOct(unsigned int bits,
                                        vector<unsigned char> const &) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateOkp(Use use, unsigned int bits) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    Result<unique_ptr<Key>> generateOkp(string const &curve,
                                        vector<unsigned char> const &x_bytes,
                                        vector<unsigned char> const &d_bytes) const override
    {
        return makeError<unique_ptr<Key>>("not implemented");
    }
    string getErrorString() const override
    {
        return string();
    }

protected:
    virtual Result<std::vector<unsigned char>>
    sign_(SignatureAlgorithm algorithm,
          Key *key,
          std::span<unsigned char const> const &data) const override
    {
        (void)algorithm;
        (void)key;
        (void)data;
        return makeOk<std::vector<unsigned char>>({});
    }
    Result<bool> verify_(SignatureAlgorithm algorithm,
                         Key *key,
                         std::vector<unsigned char> const &data,
                         std::vector<unsigned char> const &signature) const override
    {
        (void)algorithm;
        (void)key;
        (void)data;
        (void)signature;
        return makeOk<bool>(false);
    }
    Result<std::vector<unsigned char>>
    encryptKey_(KeyEncryptionAlgorithm algorithm,
                Key *key,
                std::vector<unsigned char> const &cek,
                std::optional<std::vector<unsigned char>> const &iv,
                std::optional<std::vector<unsigned char>> const &tag,
                Key *ephemeral_key,
                ContentEncryptionAlgorithm content_alg) const override
    {
        (void)algorithm;
        (void)key;
        (void)cek;
        (void)iv;
        (void)tag;
        (void)ephemeral_key;
        (void)content_alg;
        return makeOk<std::vector<unsigned char>>({});
    }
    Result<std::vector<unsigned char>>
    decryptKey_(KeyEncryptionAlgorithm algorithm,
                Key *key,
                std::vector<unsigned char> const &encrypted_cek,
                std::optional<std::vector<unsigned char>> const &iv,
                std::optional<std::vector<unsigned char>> const &tag,
                Key *ephemeral_key,
                ContentEncryptionAlgorithm content_alg) const override
    {
        (void)algorithm;
        (void)key;
        (void)encrypted_cek;
        (void)iv;
        (void)tag;
        (void)ephemeral_key;
        (void)content_alg;
        return makeOk<std::vector<unsigned char>>({});
    }
    virtual Result<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>>
    encryptContent_(ContentEncryptionAlgorithm algorithm,
                    std::vector<unsigned char> const &cek,
                    std::vector<unsigned char> const &iv,
                    std::vector<unsigned char> const &plaintext,
                    std::vector<unsigned char> const &aad) const override
    {
        (void)algorithm;
        (void)cek;
        (void)iv;
        (void)plaintext;
        (void)aad;
        return makeOk<std::pair<std::vector<unsigned char>, std::vector<unsigned char>>>({{}, {}});
    }
    virtual Result<std::vector<unsigned char>>
    decryptContent_(ContentEncryptionAlgorithm algorithm,
                    std::vector<unsigned char> const &cek,
                    std::vector<unsigned char> const &iv,
                    std::vector<unsigned char> const &ciphertext,
                    std::vector<unsigned char> const &aad,
                    std::vector<unsigned char> const &tag) const override
    {
        (void)algorithm;
        (void)cek;
        (void)iv;
        (void)ciphertext;
        (void)aad;
        (void)tag;
        return makeOk<std::vector<unsigned char>>({});
    }
};

TEST_CASE("BackEnd::concatKDF produces expected length and deterministic output")
{
    TestBackEnd backend;
    vector<unsigned char> shared_secret = {0x01, 0x02, 0x03};
    string alg = "TESTALG";

    SECTION("key length less than hash length")
    {
        size_t key_len = 16;
        auto derived = backend.concatKDF(shared_secret, key_len, alg);
        REQUIRE(derived.size() == key_len);
        REQUIRE(all_of(derived.begin(),
                       derived.end(),
                       [](unsigned char c)
                       {
                           return c == (unsigned char)0xAA;
                       }));
    }

    SECTION("key length greater than hash length")
    {
        size_t key_len = 50;
        auto derived = backend.concatKDF(shared_secret, key_len, alg);
        REQUIRE(derived.size() == key_len);
        REQUIRE(all_of(derived.begin(),
                       derived.end(),
                       [](unsigned char c)
                       {
                           return c == (unsigned char)0xAA;
                       }));
    }
}
