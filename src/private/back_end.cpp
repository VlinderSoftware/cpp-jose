#include "back_end.hpp"

#include <array>
#include <stdexcept>

#include "../jwk_impl.hpp"
#include "endian.hpp"

using namespace std;

namespace {

constexpr char const base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                      "abcdefghijklmnopqrstuvwxyz"
                                      "0123456789+/";

}  // namespace

namespace Vlinder {
namespace JOSE {
namespace Private {

vector<unsigned char>
BackEnd::concatKDF(vector<unsigned char> const &shared_secret /* Z in the spec */,
                   size_t key_data_len,
                   string const &algorithm,
                   vector<unsigned char> const &apu,
                   vector<unsigned char> const &apv) const
{
    // build AlgorithmID
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } alg_len_be;
    alg_len_be.value = toBigEndian(static_cast<uint32_t>(algorithm.length()));
    vector<unsigned char> algorithm_id;
    algorithm_id.insert(algorithm_id.end(),
                        reinterpret_cast<unsigned char const *>(&alg_len_be),
                        reinterpret_cast<unsigned char const *>(&alg_len_be) + sizeof(uint32_t));
    algorithm_id.insert(algorithm_id.end(), algorithm.begin(), algorithm.end());

    // build PartyUInfo
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } apu_len_be;
    apu_len_be.value = toBigEndian(static_cast<uint32_t>(apu.size()));
    vector<unsigned char> party_u_info;
    party_u_info.insert(party_u_info.end(),
                        reinterpret_cast<unsigned char const *>(&apu_len_be),
                        reinterpret_cast<unsigned char const *>(&apu_len_be) + sizeof(uint32_t));
    party_u_info.insert(party_u_info.end(), apu.begin(), apu.end());

    // build PartyVInfo
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } apv_len_be;
    apv_len_be.value = toBigEndian(static_cast<uint32_t>(apv.size()));
    vector<unsigned char> party_v_info;
    party_v_info.insert(party_v_info.end(),
                        reinterpret_cast<unsigned char const *>(&apv_len_be),
                        reinterpret_cast<unsigned char const *>(&apv_len_be) + sizeof(uint32_t));
    party_v_info.insert(party_v_info.end(), apv.begin(), apv.end());

    // build SuppPubInfo
    union
    {
        uint32_t value;
        unsigned char bytes[4];
    } supp_pub_info_be;
    supp_pub_info_be.value = toBigEndian(static_cast<uint32_t>(key_data_len * 8));

    // build SuppPrivInfo (empty in our case)
    vector<unsigned char> supp_priv_info;

    // Concatenate all the components to form OtherInfo
    vector<unsigned char> other_info;
    other_info.insert(other_info.end(), algorithm_id.begin(), algorithm_id.end());
    other_info.insert(other_info.end(), party_u_info.begin(), party_u_info.end());
    other_info.insert(other_info.end(), party_v_info.begin(), party_v_info.end());
    other_info.insert(other_info.end(),
                      supp_pub_info_be.bytes,
                      supp_pub_info_be.bytes + sizeof(uint32_t));
    other_info.insert(other_info.end(), supp_priv_info.begin(), supp_priv_info.end());

    // Perform the KDF rounds
    vector<unsigned char> derived_key;
    size_t hash_len = 32;  // SHA-256 output size
    size_t reps = (key_data_len + hash_len - 1) / hash_len;
    for (size_t i = 1; i <= reps; ++i)  // 1-based round counter
    {
        vector<unsigned char> round_data;
        union
        {
            uint32_t value;
            unsigned char bytes[4];
        } round_be;
        round_be.value = toBigEndian(static_cast<uint32_t>(i));
        round_data.insert(round_data.end(), round_be.bytes, round_be.bytes + sizeof(uint32_t));
        round_data.insert(round_data.end(), shared_secret.begin(), shared_secret.end());
        round_data.insert(round_data.end(), other_info.begin(), other_info.end());
        vector<unsigned char> hash = this->hash(HashAlgorithm::sha256, round_data);
        derived_key.insert(derived_key.end(), hash.begin(), hash.end());
    }
    derived_key.resize(key_data_len);
    return derived_key;
}

vector<unsigned char>
BackEnd::sign(SignatureAlgorithm algorithm, JWK const &key, vector<unsigned char> const &data) const
{
    return sign(algorithm, key, span<unsigned char const>(data.data(), data.size()));
}

vector<unsigned char> BackEnd::sign(SignatureAlgorithm algorithm,
                                    JWK const &key,
                                    span<unsigned char const> const &data) const
{
    auto underlying_key = key.impl_ ? key.impl_->key_.get() : nullptr;
    if (underlying_key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }
    // validate the key has private part and throw if not
    if (!key.hasPrivateKey())
    {
        throw runtime_error("Key does not contain private material");
    }
    // validate the algorithm against the key type and throw if not compatible
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            if (key.getKeyType() != JWK::KeyType::oct ||
                dynamic_cast<OctKey const *>(underlying_key) == nullptr)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            break;
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            if (key.getKeyType() != JWK::KeyType::rsa)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            break;
        case SignatureAlgorithm::es256:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES256")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::es384:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES384")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::es512:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES512")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::eddsa:
            if (key.getKeyType() != JWK::KeyType::okp)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            break;
        case SignatureAlgorithm::none:
            throw runtime_error("Cannot sign with 'none' algorithm");
    }
    // Delegate to back-end
    return this->sign_(algorithm, underlying_key, data);
}

bool BackEnd::verify(SignatureAlgorithm algorithm,
                     JWK const &key,
                     std::vector<unsigned char> const &data,
                     std::vector<unsigned char> const &signature) const
{
    auto underlying_key = key.impl_ ? key.impl_->key_.get() : nullptr;
    if (underlying_key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
            if (key.getKeyType() != JWK::KeyType::oct ||
                dynamic_cast<OctKey const *>(underlying_key) == nullptr)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            if (!key.hasPrivateKey())
            {
                throw runtime_error("HMAC verification requires symmetric key material");
            }
            break;
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            if (key.getKeyType() != JWK::KeyType::rsa)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            break;
        case SignatureAlgorithm::es256:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES256")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::es384:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES384")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::es512:
            if (key.getKeyType() != JWK::KeyType::ec || key.getAlgorithm() != "ES512")
            {
                throw runtime_error("Incompatible key type or curve for algorithm");
            }
            break;
        case SignatureAlgorithm::eddsa:
            if (key.getKeyType() != JWK::KeyType::okp)
            {
                throw runtime_error("Incompatible key type for algorithm");
            }
            break;
        case SignatureAlgorithm::none:
            throw runtime_error("Cannot verify with 'none' algorithm");
    }

    return this->verify_(algorithm, underlying_key, data, signature);
}

vector<unsigned char> BackEnd::encryptKey(KeyEncryptionAlgorithm algorithm,
                                          const JWK &key,
                                          vector<unsigned char> const &cek,
                                          optional<vector<unsigned char>> const &iv,
                                          optional<vector<unsigned char>> const &tag,
                                          optional<JWK> const &ephemeral_key,
                                          ContentEncryptionAlgorithm content_alg) const
{
    auto underlying_key = key.impl_ ? key.impl_->key_.get() : nullptr;
    if (underlying_key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }
    auto underlying_ephemeral_key =
        ephemeral_key ? (*ephemeral_key).impl_ ? (*ephemeral_key).impl_->key_.get() : nullptr
                      : nullptr;
    return this->encryptKey_(algorithm,
                             underlying_key,
                             cek,
                             iv,
                             tag,
                             underlying_ephemeral_key,
                             content_alg);
}

vector<unsigned char> BackEnd::decryptKey(KeyEncryptionAlgorithm algorithm,
                                          JWK const &key,
                                          vector<unsigned char> const &encrypted_cek,
                                          optional<vector<unsigned char>> const &iv,
                                          optional<vector<unsigned char>> const &tag,
                                          optional<JWK> const &ephemeral_key,
                                          ContentEncryptionAlgorithm content_alg) const
{
    auto underlying_key = key.impl_ ? key.impl_->key_.get() : nullptr;
    if (underlying_key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }
    auto underlying_ephemeral_key =
        ephemeral_key ? (*ephemeral_key).impl_ ? (*ephemeral_key).impl_->key_.get() : nullptr
                      : nullptr;
    return this->decryptKey_(algorithm,
                             underlying_key,
                             encrypted_cek,
                             iv,
                             tag,
                             underlying_ephemeral_key,
                             content_alg);
}

pair<vector<unsigned char>, vector<unsigned char>>
BackEnd::encryptContent(ContentEncryptionAlgorithm algorithm,
                        vector<unsigned char> const &cek,
                        vector<unsigned char> const &iv,
                        vector<unsigned char> const &plaintext,
                        vector<unsigned char> const &aad) const
{
    return this->encryptContent_(algorithm, cek, iv, plaintext, aad);
}

vector<unsigned char> BackEnd::decryptContent(ContentEncryptionAlgorithm algorithm,
                                              vector<unsigned char> const &cek,
                                              vector<unsigned char> const &iv,
                                              vector<unsigned char> const &ciphertext,
                                              vector<unsigned char> const &aad,
                                              vector<unsigned char> const &tag) const
{
    return this->decryptContent_(algorithm, cek, iv, ciphertext, aad, tag);
}

string BackEnd::base64Encode(span<unsigned char const> const &data) const
{
    if (data.empty())
    {
        return {};
    }

    string out;
    out.reserve(4 * ((data.size() + 2) / 3));

    size_t i = 0;
    for (; i + 2 < data.size(); i += 3)
    {
        uint32_t const triple = (static_cast<uint32_t>(data[i]) << 16) |
                                (static_cast<uint32_t>(data[i + 1]) << 8) |
                                static_cast<uint32_t>(data[i + 2]);
        out.push_back(base64_chars[(triple >> 18) & 0x3F]);
        out.push_back(base64_chars[(triple >> 12) & 0x3F]);
        out.push_back(base64_chars[(triple >> 6) & 0x3F]);
        out.push_back(base64_chars[(triple) & 0x3F]);
    }
    size_t const remaining = data.size() - i;
    if (remaining == 1)
    {
        uint32_t const triple = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(base64_chars[(triple >> 18) & 0x3F]);
        out.push_back(base64_chars[(triple >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    }
    else if (remaining == 2)
    {
        uint32_t const triple =
            (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(base64_chars[(triple >> 18) & 0x3F]);
        out.push_back(base64_chars[(triple >> 12) & 0x3F]);
        out.push_back(base64_chars[(triple >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

string BackEnd::base64Encode(vector<unsigned char> const &data) const
{
    return base64Encode(span<unsigned char const>(data.data(), data.size()));
}

vector<unsigned char> BackEnd::base64Decode(string const &encoded) const
{
    if (encoded.empty())
    {
        return {};
    }

    // Build reverse lookup: accepts both standard (+/) and URL-safe (-_) alphabet
    static array<int8_t, 256> const kDecodeTable = []()
    {
        array<int8_t, 256> t;
        t.fill(-1);
        for (int i = 0; i < 26; ++i)
        {
            t[static_cast<unsigned char>('A' + i)] = static_cast<int8_t>(i);
            t[static_cast<unsigned char>('a' + i)] = static_cast<int8_t>(26 + i);
        }
        for (int i = 0; i < 10; ++i)
        {
            t[static_cast<unsigned char>('0' + i)] = static_cast<int8_t>(52 + i);
        }
        t[static_cast<unsigned char>('+')] = 62;
        t[static_cast<unsigned char>('/')] = 63;
        t[static_cast<unsigned char>('-')] = 62;  // URL-safe
        t[static_cast<unsigned char>('_')] = 63;  // URL-safe
        t[static_cast<unsigned char>('=')] = 0;   // padding (treated as zero)
        return t;
    }();

    // Strip whitespace
    string cleaned;
    cleaned.reserve(encoded.size());
    for (unsigned char c : encoded)
    {
        if (c != '\r' && c != '\n' && c != ' ')
        {
            cleaned.push_back(static_cast<char>(c));
        }
    }

    if (cleaned.empty())
    {
        return {};
    }

    if ((cleaned.size() % 4) != 0)
    {
        throw runtime_error("Invalid base64 input length");
    }

    size_t padding = 0;
    if (cleaned.back() == '=')
        ++padding;
    if (cleaned.size() > 1 && cleaned[cleaned.size() - 2] == '=')
        ++padding;

    vector<unsigned char> out;
    out.reserve((cleaned.size() / 4) * 3 - padding);

    for (size_t i = 0; i < cleaned.size(); i += 4)
    {
        int8_t const v0 = kDecodeTable[static_cast<unsigned char>(cleaned[i])];
        int8_t const v1 = kDecodeTable[static_cast<unsigned char>(cleaned[i + 1])];
        int8_t const v2 = kDecodeTable[static_cast<unsigned char>(cleaned[i + 2])];
        int8_t const v3 = kDecodeTable[static_cast<unsigned char>(cleaned[i + 3])];

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
        {
            throw runtime_error("Invalid character in base64 input");
        }

        uint32_t const triple = (static_cast<uint32_t>(v0) << 18) |
                                (static_cast<uint32_t>(v1) << 12) |
                                (static_cast<uint32_t>(v2) << 6) | static_cast<uint32_t>(v3);

        out.push_back(static_cast<unsigned char>((triple >> 16) & 0xFF));
        if (cleaned[i + 2] != '=')
        {
            out.push_back(static_cast<unsigned char>((triple >> 8) & 0xFF));
        }
        if (cleaned[i + 3] != '=')
        {
            out.push_back(static_cast<unsigned char>(triple & 0xFF));
        }
    }

    return out;
}

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
