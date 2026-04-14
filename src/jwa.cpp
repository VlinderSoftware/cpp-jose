#include "jwa.hpp"

#include <map>
#include <mutex>
#include <stdexcept>

#include "private/back_end_factory.hpp"
#include "private/result.hpp"

using namespace std;
using namespace Vlinder::JOSE::Private;

namespace Vlinder {
namespace JOSE {
namespace {
Private::BackEnd &getBackEnd()
{
    static once_flag flag;

    static unique_ptr<Private::BackEnd> back_end;
    call_once(flag,
              []()
              {
                  Private::BackEndFactory &factory(Private::BackEndFactory::get());
                  back_end = std::move(factory.createBackEnd());
              });

    return *back_end;
}
}  // namespace

bool JWA::verify(SignatureAlgorithm algorithm,
                 const JWK &key,
                 std::vector<unsigned char> const &data,
                 std::vector<unsigned char> const &signature)
{
    return getBackEnd().verify(algorithm, key, data, signature);
}

vector<unsigned char> JWA::encryptKey(KeyEncryptionAlgorithm algorithm,
                                      const JWK &key,
                                      vector<unsigned char> const &cek,
                                      optional<vector<unsigned char>> const &iv,
                                      optional<vector<unsigned char>> const &tag,
                                      optional<JWK> const &ephemeral_key,
                                      ContentEncryptionAlgorithm content_alg)
{
    return getBackEnd().encryptKey(algorithm, key, cek, iv, tag, ephemeral_key, content_alg);
}

vector<unsigned char> JWA::decryptKey(KeyEncryptionAlgorithm algorithm,
                                      JWK const &key,
                                      vector<unsigned char> const &encrypted_cek,
                                      optional<vector<unsigned char>> const &iv,
                                      optional<vector<unsigned char>> const &tag,
                                      optional<JWK> const &ephemeral_key,
                                      ContentEncryptionAlgorithm content_alg)
{
    return getBackEnd()
        .decryptKey(algorithm, key, encrypted_cek, iv, tag, ephemeral_key, content_alg);
}

pair<vector<unsigned char>, vector<unsigned char>>
JWA::encryptContent(ContentEncryptionAlgorithm algorithm,
                    vector<unsigned char> const &cek,
                    vector<unsigned char> const &iv,
                    vector<unsigned char> const &plaintext,
                    vector<unsigned char> const &aad)
{
    return getBackEnd().encryptContent(algorithm, cek, iv, plaintext, aad);
}

vector<unsigned char> JWA::decryptContent(ContentEncryptionAlgorithm algorithm,
                                          vector<unsigned char> const &cek,
                                          vector<unsigned char> const &iv,
                                          vector<unsigned char> const &ciphertext,
                                          vector<unsigned char> const &aad,
                                          vector<unsigned char> const &tag)
{
    return getBackEnd().decryptContent(algorithm, cek, iv, ciphertext, aad, tag);
}

string JWA::toString(SignatureAlgorithm alg)
{
    static map<SignatureAlgorithm, string> const alg_map = {{SignatureAlgorithm::hs256, "HS256"},
                                                            {SignatureAlgorithm::hs384, "HS384"},
                                                            {SignatureAlgorithm::hs512, "HS512"},
                                                            {SignatureAlgorithm::rs256, "RS256"},
                                                            {SignatureAlgorithm::rs384, "RS384"},
                                                            {SignatureAlgorithm::rs512, "RS512"},
                                                            {SignatureAlgorithm::es256, "ES256"},
                                                            {SignatureAlgorithm::es384, "ES384"},
                                                            {SignatureAlgorithm::es512, "ES512"},
                                                            {SignatureAlgorithm::ps256, "PS256"},
                                                            {SignatureAlgorithm::ps384, "PS384"},
                                                            {SignatureAlgorithm::ps512, "PS512"},
                                                            {SignatureAlgorithm::eddsa, "EdDSA"},
                                                            {SignatureAlgorithm::none, "none"}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        throw runtime_error("Unknown signature algorithm");
    }
    return it->second;
}

string JWA::toString(KeyEncryptionAlgorithm alg)
{
    static map<KeyEncryptionAlgorithm, string> const alg_map = {
        {KeyEncryptionAlgorithm::rsa1_5, "RSA1_5"},
        {KeyEncryptionAlgorithm::rsa_oaep, "RSA-OAEP"},
        {KeyEncryptionAlgorithm::rsa_oaep_256, "RSA-OAEP-256"},
        {KeyEncryptionAlgorithm::a128kw, "A128KW"},
        {KeyEncryptionAlgorithm::a192kw, "A192KW"},
        {KeyEncryptionAlgorithm::a256kw, "A256KW"},
        {KeyEncryptionAlgorithm::dir, "dir"},
        {KeyEncryptionAlgorithm::ecdh_es, "ECDH-ES"},
        {KeyEncryptionAlgorithm::a128gcmkw, "A128GCMKW"},
        {KeyEncryptionAlgorithm::a192gcmkw, "A192GCMKW"},
        {KeyEncryptionAlgorithm::a256gcmkw, "A256GCMKW"}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        throw runtime_error("Unknown key encryption algorithm");
    }
    return it->second;
}

string JWA::toString(ContentEncryptionAlgorithm alg)
{
    static map<ContentEncryptionAlgorithm, string> const alg_map = {
        {ContentEncryptionAlgorithm::a128cbc_hs256, "A128CBC-HS256"},
        {ContentEncryptionAlgorithm::a192cbc_hs384, "A192CBC-HS384"},
        {ContentEncryptionAlgorithm::a256cbc_hs512, "A256CBC-HS512"},
        {ContentEncryptionAlgorithm::a128gcm, "A128GCM"},
        {ContentEncryptionAlgorithm::a192gcm, "A192GCM"},
        {ContentEncryptionAlgorithm::a256gcm, "A256GCM"}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        throw runtime_error("Unknown content encryption algorithm");
    }
    return it->second;
}

namespace {
Result<JWA::SignatureAlgorithm> signatureAlgorithmFromString_(string const &alg) noexcept
{
    static map<string, JWA::SignatureAlgorithm> const alg_map = {
        {"HS256", JWA::SignatureAlgorithm::hs256},
        {"HS384", JWA::SignatureAlgorithm::hs384},
        {"HS512", JWA::SignatureAlgorithm::hs512},
        {"RS256", JWA::SignatureAlgorithm::rs256},
        {"RS384", JWA::SignatureAlgorithm::rs384},
        {"RS512", JWA::SignatureAlgorithm::rs512},
        {"ES256", JWA::SignatureAlgorithm::es256},
        {"ES384", JWA::SignatureAlgorithm::es384},
        {"ES512", JWA::SignatureAlgorithm::es512},
        {"PS256", JWA::SignatureAlgorithm::ps256},
        {"PS384", JWA::SignatureAlgorithm::ps384},
        {"PS512", JWA::SignatureAlgorithm::ps512},
        {"EdDSA", JWA::SignatureAlgorithm::eddsa},
        {"none", JWA::SignatureAlgorithm::none}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        return makeError<JWA::SignatureAlgorithm>("Unknown signature algorithm: " + alg);
    }
    return makeOk(it->second);
}

Result<JWA::KeyEncryptionAlgorithm> keyEncryptionAlgorithmFromString_(string const &alg) noexcept
{
    static map<string, JWA::KeyEncryptionAlgorithm> const alg_map = {
        {"RSA1_5", JWA::KeyEncryptionAlgorithm::rsa1_5},
        {"RSA-OAEP", JWA::KeyEncryptionAlgorithm::rsa_oaep},
        {"RSA-OAEP-256", JWA::KeyEncryptionAlgorithm::rsa_oaep_256},
        {"A128KW", JWA::KeyEncryptionAlgorithm::a128kw},
        {"A192KW", JWA::KeyEncryptionAlgorithm::a192kw},
        {"A256KW", JWA::KeyEncryptionAlgorithm::a256kw},
        {"dir", JWA::KeyEncryptionAlgorithm::dir},
        {"ECDH-ES", JWA::KeyEncryptionAlgorithm::ecdh_es},
        {"A128GCMKW", JWA::KeyEncryptionAlgorithm::a128gcmkw},
        {"A192GCMKW", JWA::KeyEncryptionAlgorithm::a192gcmkw},
        {"A256GCMKW", JWA::KeyEncryptionAlgorithm::a256gcmkw}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        return makeError<JWA::KeyEncryptionAlgorithm>("Unknown key encryption algorithm: " + alg);
    }
    return makeOk(it->second);
}

Result<JWA::ContentEncryptionAlgorithm>
contentEncryptionAlgorithmFromString_(string const &alg) noexcept
{
    static map<string, JWA::ContentEncryptionAlgorithm> const alg_map = {
        {"A128CBC-HS256", JWA::ContentEncryptionAlgorithm::a128cbc_hs256},
        {"A192CBC-HS384", JWA::ContentEncryptionAlgorithm::a192cbc_hs384},
        {"A256CBC-HS512", JWA::ContentEncryptionAlgorithm::a256cbc_hs512},
        {"A128GCM", JWA::ContentEncryptionAlgorithm::a128gcm},
        {"A192GCM", JWA::ContentEncryptionAlgorithm::a192gcm},
        {"A256GCM", JWA::ContentEncryptionAlgorithm::a256gcm}};

    auto it = alg_map.find(alg);
    if (it == alg_map.end())
    {
        return makeError<JWA::ContentEncryptionAlgorithm>("Unknown content encryption algorithm: " +
                                                          alg);
    }
    return makeOk(it->second);
}
}  // namespace

JWA::SignatureAlgorithm JWA::signatureAlgorithmFromString(string const &alg)
{
    auto [result, error] = signatureAlgorithmFromString_(alg);
    if (!result)
    {
        throw runtime_error(error);
    }
    return *result;
}

JWA::KeyEncryptionAlgorithm JWA::keyEncryptionAlgorithmFromString(string const &alg)
{
    auto [result, error] = keyEncryptionAlgorithmFromString_(alg);
    if (!result)
    {
        throw runtime_error(error);
    }
    return *result;
}

JWA::ContentEncryptionAlgorithm JWA::contentEncryptionAlgorithmFromString(string const &alg)
{
    auto [result, error] = contentEncryptionAlgorithmFromString_(alg);
    if (!result)
    {
        throw runtime_error(error);
    }
    return *result;
}

optional<JWA::SignatureAlgorithm> JWA::signatureAlgorithmFromString(string const &alg,
                                                                    nothrow_t const &) noexcept
{
    return signatureAlgorithmFromString_(alg).first;
}

optional<JWA::KeyEncryptionAlgorithm>
JWA::keyEncryptionAlgorithmFromString(string const &alg, nothrow_t const &) noexcept
{
    return keyEncryptionAlgorithmFromString_(alg).first;
}

optional<JWA::ContentEncryptionAlgorithm>
JWA::contentEncryptionAlgorithmFromString(string const &alg, nothrow_t const &) noexcept
{
    return contentEncryptionAlgorithmFromString_(alg).first;
}

}  // namespace JOSE
}  // namespace Vlinder
