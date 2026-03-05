#include "../src/private/back_end.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace Vlinder::JOSE::Private;
using namespace std;

// Minimal test backend that provides a deterministic "hash" implementation
// returning 32 bytes of 0xAA for any input. This lets concatKDF behavior be
// predicted without depending on OpenSSL/CNG.
class TestBackEnd : public BackEnd
{
public:
    std::vector<unsigned char> hash(HashAlgorithm /*algorithm*/, vector<unsigned char> const& /*data*/) const override
    {
        return vector<unsigned char>(32, 0xAA);
    }

    string base64Encode(vector<unsigned char> const& /*data*/) const override
    {
        return string();
    }
    vector<unsigned char> base64Decode(string const& /*encoded*/) const override
    {
        return {};
    }
    unique_ptr<Key> generateRSA(unsigned int bits) const override
    {
        return nullptr;
    }
    unique_ptr<Key> generateRSA(vector<unsigned char> const& n_bytes,
                                     vector<unsigned char> const& e_bytes,
                                     vector<unsigned char> const& d_bytes,
                                     vector<unsigned char> const& p_bytes,
                                     vector<unsigned char> const& q_bytes,
                                     vector<unsigned char> const& dp_bytes,
                                     vector<unsigned char> const& dq_bytes,
                                     vector<unsigned char> const& qi_bytes) const override
    {
        return nullptr;
    }
    unique_ptr<Key> generateEC(string const&) const override
    {
        return nullptr;
    }
    unique_ptr<Key> generateEC(string const&, vector<unsigned char> const&,
                               vector<unsigned char> const&,
                               vector<unsigned char> const&) const override
    {
        return nullptr;
    }
    unique_ptr<Key> generateOct(unsigned int bits) const override
    {
        return nullptr;
    }
    unique_ptr<Key> generateOkp(Use use, unsigned int bits) const override
    {
        return nullptr;
    }
    string getErrorString() const override
    {
        return string();
    }
};

TEST_CASE("BackEnd::concatKDF produces expected length and deterministic output")
{
    TestBackEnd backend;
    vector<unsigned char> shared_secret = { 0x01, 0x02, 0x03 };
    string alg = "TESTALG";

    SECTION("key length less than hash length")
    {
        size_t key_len = 16;
        auto derived = backend.concatKDF(shared_secret, key_len, alg);
        REQUIRE(derived.size() == key_len);
        REQUIRE(all_of(derived.begin(), derived.end(), [](unsigned char c) { return c == (unsigned char)0xAA; }));
    }

    SECTION("key length greater than hash length")
    {
        size_t key_len = 50;
        auto derived = backend.concatKDF(shared_secret, key_len, alg);
        REQUIRE(derived.size() == key_len);
        REQUIRE(all_of(derived.begin(), derived.end(), [](unsigned char c) { return c == (unsigned char)0xAA; }));
    }
}
