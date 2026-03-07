#include "jwa.hpp"

#include <map>
#include <stdexcept>

using namespace std;

namespace Vlinder {
namespace JOSE {

string JWA::toString(SignatureAlgorithm alg)
{
    static const map<SignatureAlgorithm, string> alg_map = {{SignatureAlgorithm::hs256, "HS256"},
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
                                                            {SignatureAlgorithm::none, "none"}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown signature algorithm");
}

string JWA::toString(KeyEncryptionAlgorithm alg)
{
    static const map<KeyEncryptionAlgorithm, string> alg_map = {
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
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown key encryption algorithm");
}

string JWA::toString(ContentEncryptionAlgorithm alg)
{
    static const map<ContentEncryptionAlgorithm, string> alg_map = {
        {ContentEncryptionAlgorithm::a128cbc_hs256, "A128CBC-HS256"},
        {ContentEncryptionAlgorithm::a192cbc_hs384, "A192CBC-HS384"},
        {ContentEncryptionAlgorithm::a256cbc_hs512, "A256CBC-HS512"},
        {ContentEncryptionAlgorithm::a128gcm, "A128GCM"},
        {ContentEncryptionAlgorithm::a192gcm, "A192GCM"},
        {ContentEncryptionAlgorithm::a256gcm, "A256GCM"}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown content encryption algorithm");
}

JWA::SignatureAlgorithm JWA::signatureAlgorithmFromString(const string &alg)
{
    static const map<string, SignatureAlgorithm> alg_map = {{"HS256", SignatureAlgorithm::hs256},
                                                            {"HS384", SignatureAlgorithm::hs384},
                                                            {"HS512", SignatureAlgorithm::hs512},
                                                            {"RS256", SignatureAlgorithm::rs256},
                                                            {"RS384", SignatureAlgorithm::rs384},
                                                            {"RS512", SignatureAlgorithm::rs512},
                                                            {"ES256", SignatureAlgorithm::es256},
                                                            {"ES384", SignatureAlgorithm::es384},
                                                            {"ES512", SignatureAlgorithm::es512},
                                                            {"PS256", SignatureAlgorithm::ps256},
                                                            {"PS384", SignatureAlgorithm::ps384},
                                                            {"PS512", SignatureAlgorithm::ps512},
                                                            {"none", SignatureAlgorithm::none}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown signature algorithm: " + alg);
}

JWA::KeyEncryptionAlgorithm JWA::keyEncryptionAlgorithmFromString(const string &alg)
{
    static const map<string, KeyEncryptionAlgorithm> alg_map = {
        {"RSA1_5", KeyEncryptionAlgorithm::rsa1_5},
        {"RSA-OAEP", KeyEncryptionAlgorithm::rsa_oaep},
        {"RSA-OAEP-256", KeyEncryptionAlgorithm::rsa_oaep_256},
        {"A128KW", KeyEncryptionAlgorithm::a128kw},
        {"A192KW", KeyEncryptionAlgorithm::a192kw},
        {"A256KW", KeyEncryptionAlgorithm::a256kw},
        {"dir", KeyEncryptionAlgorithm::dir},
        {"ECDH-ES", KeyEncryptionAlgorithm::ecdh_es},
        {"A128GCMKW", KeyEncryptionAlgorithm::a128gcmkw},
        {"A192GCMKW", KeyEncryptionAlgorithm::a192gcmkw},
        {"A256GCMKW", KeyEncryptionAlgorithm::a256gcmkw}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown key encryption algorithm: " + alg);
}

JWA::ContentEncryptionAlgorithm JWA::contentEncryptionAlgorithmFromString(const string &alg)
{
    static const map<string, ContentEncryptionAlgorithm> alg_map = {
        {"A128CBC-HS256", ContentEncryptionAlgorithm::a128cbc_hs256},
        {"A192CBC-HS384", ContentEncryptionAlgorithm::a192cbc_hs384},
        {"A256CBC-HS512", ContentEncryptionAlgorithm::a256cbc_hs512},
        {"A128GCM", ContentEncryptionAlgorithm::a128gcm},
        {"A192GCM", ContentEncryptionAlgorithm::a192gcm},
        {"A256GCM", ContentEncryptionAlgorithm::a256gcm}};

    auto it = alg_map.find(alg);
    if (it != alg_map.end())
    {
        return it->second;
    }

    throw runtime_error("Unknown content encryption algorithm: " + alg);
}

}  // namespace JOSE
}  // namespace Vlinder
