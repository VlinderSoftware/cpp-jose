#include "jwe.hpp"

#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>

#include "base64url.hpp"
#include "private/json_utils.hpp"
#include "jwa.hpp"
#include "jwk.hpp"

using namespace std;
using json = Vlinder::JOSE::Private::json;
namespace Vlinder {
namespace JOSE {

namespace {

vector<unsigned char> getOctetKeyMaterial(JWK const &key)
{
    json const key_json = json::parse(key.toJSON(true));
    if (!key_json.contains("kty") || key_json["kty"].get<string>() != "oct")
    {
        throw runtime_error("Direct key mode requires an oct JWK");
    }
    if (!key_json.contains("k"))
    {
        throw runtime_error("oct JWK missing required 'k' field");
    }

    return Base64Url::decode(key_json["k"].get<string>());
}

vector<unsigned char> generateRandomBytes(size_t byte_count)
{
    if (byte_count == 0)
    {
        return {};
    }

    JWK random_key = JWK::generateOct(JWK::Use::encryption, static_cast<int>(byte_count * 8));
    vector<unsigned char> bytes = getOctetKeyMaterial(random_key);
    if (bytes.size() != byte_count)
    {
        throw runtime_error("Failed to generate random bytes of requested length");
    }
    return bytes;
}

size_t getKeySize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::a128gcm:
            return 16;  // 128 bits for AES-128-GCM
        case JWA::ContentEncryptionAlgorithm::a128cbc_hs256:
            return 32;  // 256 bits for A128CBC_HS256 (128 for AES + 128 for HMAC)
        case JWA::ContentEncryptionAlgorithm::a192gcm:
            return 24;  // 192 bits for AES-192-GCM
        case JWA::ContentEncryptionAlgorithm::a192cbc_hs384:
            return 48;  // 384 bits
        case JWA::ContentEncryptionAlgorithm::a256gcm:
            return 32;  // 256 bits for AES-256-GCM
        case JWA::ContentEncryptionAlgorithm::a256cbc_hs512:
            return 64;  // 512 bits for A256CBC_HS512
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

size_t getIVSize(JWA::ContentEncryptionAlgorithm algorithm)
{
    switch (algorithm)
    {
        case JWA::ContentEncryptionAlgorithm::a128gcm:
        case JWA::ContentEncryptionAlgorithm::a192gcm:
        case JWA::ContentEncryptionAlgorithm::a256gcm:
            return 12;  // 96 bits for GCM
        case JWA::ContentEncryptionAlgorithm::a128cbc_hs256:
        case JWA::ContentEncryptionAlgorithm::a192cbc_hs384:
        case JWA::ContentEncryptionAlgorithm::a256cbc_hs512:
            return 16;  // 128 bits for CBC
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

}  // anonymous namespace

struct JWE::Impl
{
    string plaintext_;
    JWA::KeyEncryptionAlgorithm key_algorithm_ = JWA::KeyEncryptionAlgorithm::rsa_oaep;
    JWA::ContentEncryptionAlgorithm content_algorithm_ = JWA::ContentEncryptionAlgorithm::a256gcm;
    string kid_;
    string typ_;
    map<string, string> header_params_;
    string header_json_;
};

JWE::JWE() : impl_(make_unique<Impl>())
{
}

JWE::~JWE() = default;

JWE::JWE(const JWE &other) : impl_(make_unique<Impl>(*other.impl_))
{
}

JWE &JWE::operator=(const JWE &other)
{
    if (this != &other)
    {
        impl_ = make_unique<Impl>(*other.impl_);
    }
    return *this;
}

JWE::JWE(JWE &&other) noexcept = default;
JWE &JWE::operator=(JWE &&other) noexcept = default;

void JWE::setPlaintext(string const &plaintext)
{
    impl_->plaintext_ = plaintext;
}

void JWE::setKeyEncryptionAlgorithm(JWA::KeyEncryptionAlgorithm algorithm)
{
    impl_->key_algorithm_ = algorithm;
}

void JWE::setContentEncryptionAlgorithm(JWA::ContentEncryptionAlgorithm algorithm)
{
    impl_->content_algorithm_ = algorithm;
}

void JWE::setKeyID(string const &kid)
{
    impl_->kid_ = kid;
}

void JWE::setType(string const &typ)
{
    impl_->typ_ = typ;
}

void JWE::setHeaderParam(string const &name, string const &value)
{
    impl_->header_params_[name] = value;
}

string JWE::encrypt(const JWK &key) const
{
    // Build JOSE header
    json header = json::object();
    header["alg"] = JWA::toString(impl_->key_algorithm_);
    header["enc"] = JWA::toString(impl_->content_algorithm_);

    if (!impl_->typ_.empty())
    {
        header["typ"] = impl_->typ_;
    }

    if (!impl_->kid_.empty())
    {
        header["kid"] = impl_->kid_;
    }

    // Add custom header parameters
    for (auto const &param : impl_->header_params_)
    {
        header[param.first] = param.second;
    }

    // Generate or use CEK (Content Encryption Key)
    vector<unsigned char> cek;
    vector<unsigned char> encrypted_key;
    vector<unsigned char> kek_iv;   // For GCM key wrap
    vector<unsigned char> kek_tag;  // For GCM key wrap
    optional<JWK> ephemeral_key;    // For ECDH-ES

    if (impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::dir)
    {
        // For direct encryption, use the provided key directly as the CEK
        encrypted_key.clear();  // No encrypted key field
        cek = getOctetKeyMaterial(key);
    }
    else if (impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::ecdh_es)
    {
        // For ECDH-ES, derive the CEK using key agreement
        encrypted_key.clear();  // No encrypted key field

        // Initialize ephemeral_key with dummy that will be overwritten by encryptKey
        ephemeral_key = JWK::generateEC(JWK::Use::signature, "P-256");

        // Call encryptKey which will generate ephemeral key, perform ECDH, and derive CEK
        size_t cek_size = getKeySize(impl_->content_algorithm_);
        vector<unsigned char> dummy_cek(cek_size);  // Provide size hint
        cek = JWA::encryptKey(impl_->key_algorithm_,
                              key,
                              dummy_cek,
                              {},
                              {},
                              ephemeral_key,
                              impl_->content_algorithm_);
    }
    else
    {
        // Generate random CEK and encrypt it with the key
        size_t cek_size = getKeySize(impl_->content_algorithm_);
        cek = generateRandomBytes(cek_size);

        // Check if this is a GCM key wrap algorithm
        bool is_gcm_kw = (impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::a128gcmkw ||
                          impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::a192gcmkw ||
                          impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::a256gcmkw);

        if (is_gcm_kw)
        {
            encrypted_key = JWA::encryptKey(impl_->key_algorithm_,
                                            key,
                                            cek,
                                            kek_iv,
                                            kek_tag,
                                            {},
                                            impl_->content_algorithm_);
        }
        else
        {
            encrypted_key = JWA::encryptKey(impl_->key_algorithm_,
                                            key,
                                            cek,
                                            {},
                                            {},
                                            {},
                                            impl_->content_algorithm_);
        }
    }

    // Add ephemeral public key to header if present (ECDH-ES)
    if (impl_->key_algorithm_ == JWA::KeyEncryptionAlgorithm::ecdh_es && ephemeral_key)
    {
        // Include ephemeral public key in header as JWK
        header["epk"] = json::parse(ephemeral_key->toJSON(false));
    }

    // Add GCM key wrap IV and tag to header if present
    if (!kek_iv.empty())
    {
        header["iv"] = Base64Url::encode(kek_iv);
    }
    if (!kek_tag.empty())
    {
        header["tag"] = Base64Url::encode(kek_tag);
    }

    // Now encode the header with all fields
    string header_json = header.dump();
    string encoded_header = Base64Url::encode(header_json);

    string encoded_encrypted_key = Base64Url::encode(encrypted_key);

    // Generate IV
    size_t iv_size = getIVSize(impl_->content_algorithm_);
    vector<unsigned char> iv = generateRandomBytes(iv_size);
    string encoded_iv = Base64Url::encode(iv);

    // Prepare AAD (Additional Authenticated Data) - the encoded header
    vector<unsigned char> aad(encoded_header.begin(), encoded_header.end());

    // Encrypt content
    vector<unsigned char> plaintext_bytes(impl_->plaintext_.begin(), impl_->plaintext_.end());
    auto [ciphertext, auth_tag] =
        JWA::encryptContent(impl_->content_algorithm_, cek, iv, plaintext_bytes, aad);

    string encoded_ciphertext = Base64Url::encode(ciphertext);
    string encoded_auth_tag = Base64Url::encode(auth_tag);

    // Return compact serialization: header.encrypted_key.iv.ciphertext.auth_tag
    return encoded_header + "." + encoded_encrypted_key + "." + encoded_iv + "." +
           encoded_ciphertext + "." + encoded_auth_tag;
}

string JWE::decrypt(string const &jwe, const JWK &key)
{
    // Split into five parts
    vector<string> parts;
    size_t start = 0;
    size_t pos = 0;

    while ((pos = jwe.find('.', start)) != string::npos)
    {
        parts.push_back(jwe.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(jwe.substr(start));

    if (parts.size() != 5)
    {
        throw runtime_error("Invalid JWE format: expected 5 parts");
    }

    string encoded_header = parts[0];
    string encoded_encrypted_key = parts[1];
    string encoded_iv = parts[2];
    string encoded_ciphertext = parts[3];
    string encoded_auth_tag = parts[4];

    // Decode header to get algorithms
    string header_json = Base64Url::decodeToString(encoded_header);
    json header = json::parse(header_json);

    if (!header.contains("alg") || !header.contains("enc"))
    {
        throw runtime_error("JWE header missing required algorithm fields");
    }

    string alg_str = header["alg"].get<string>();
    string enc_str = header["enc"].get<string>();

    JWA::KeyEncryptionAlgorithm key_alg = JWA::keyEncryptionAlgorithmFromString(alg_str);
    JWA::ContentEncryptionAlgorithm content_alg =
        JWA::contentEncryptionAlgorithmFromString(enc_str);

    // Decrypt CEK
    vector<unsigned char> cek;
    if (key_alg == JWA::KeyEncryptionAlgorithm::dir)
    {
        // For direct encryption, use the provided key directly as the CEK
        cek = getOctetKeyMaterial(key);
    }
    else if (key_alg == JWA::KeyEncryptionAlgorithm::ecdh_es)
    {
        // For ECDH-ES, extract ephemeral public key from header and derive CEK
        if (!header.contains("epk"))
        {
            throw runtime_error("ECDH-ES requires ephemeral public key in header");
        }

        // Parse ephemeral public key from header
        json epk_json = header["epk"];
        JWK ephemeral_key = JWK::fromJSON(epk_json.dump());

        // Derive CEK using ECDH
        vector<unsigned char> encrypted_key;  // Empty for ECDH-ES
        cek = JWA::decryptKey(key_alg,
                              key,
                              encrypted_key,
                              {},
                              {},
                              ephemeral_key,
                              content_alg);
    }
    else
    {
        vector<unsigned char> encrypted_key = Base64Url::decode(encoded_encrypted_key);

        // Check for GCM key wrap IV and tag in header
        vector<unsigned char> kek_iv;
        vector<unsigned char> kek_tag;

        if (header.contains("iv"))
        {
            kek_iv = Base64Url::decode(header["iv"].get<string>());
        }
        if (header.contains("tag"))
        {
            kek_tag = Base64Url::decode(header["tag"].get<string>());
        }

        // Pass IV and tag if present (for GCM key wrap)
        if (!kek_iv.empty() && !kek_tag.empty())
        {
            cek = JWA::decryptKey(key_alg,
                                  key,
                                  encrypted_key,
                                  kek_iv,
                                  kek_tag,
                                  {},
                                  content_alg);
        }
        else
        {
            cek = JWA::decryptKey(key_alg,
                                  key,
                                  encrypted_key,
                                  {},
                                  {},
                                  {},
                                  content_alg);
        }
    }

    // Decode other components
    vector<unsigned char> iv = Base64Url::decode(encoded_iv);
    vector<unsigned char> ciphertext = Base64Url::decode(encoded_ciphertext);
    vector<unsigned char> auth_tag = Base64Url::decode(encoded_auth_tag);

    // Prepare AAD
    vector<unsigned char> aad(encoded_header.begin(), encoded_header.end());

    // Decrypt content
    vector<unsigned char> plaintext =
        JWA::decryptContent(content_alg, cek, iv, ciphertext, aad, auth_tag);

    return string(plaintext.begin(), plaintext.end());
}

JWE JWE::parse(string const &jwe)
{
    // Split into five parts
    vector<string> parts;
    size_t start = 0;
    size_t pos = 0;

    while ((pos = jwe.find('.', start)) != string::npos)
    {
        parts.push_back(jwe.substr(start, pos - start));
        start = pos + 1;
    }
    parts.push_back(jwe.substr(start));

    if (parts.size() != 5)
    {
        throw runtime_error("Invalid JWE format: expected 5 parts");
    }

    string encoded_header = parts[0];

    // Decode header
    string header_json = Base64Url::decodeToString(encoded_header);
    json header = json::parse(header_json);

    JWE result;
    result.impl_->header_json_ = header_json;

    if (header.contains("alg"))
    {
        string alg_str = header["alg"].get<string>();
        result.impl_->key_algorithm_ = JWA::keyEncryptionAlgorithmFromString(alg_str);
    }

    if (header.contains("enc"))
    {
        string enc_str = header["enc"].get<string>();
        result.impl_->content_algorithm_ = JWA::contentEncryptionAlgorithmFromString(enc_str);
    }

    if (header.contains("kid"))
    {
        result.impl_->kid_ = header["kid"].get<string>();
    }

    if (header.contains("typ"))
    {
        result.impl_->typ_ = header["typ"].get<string>();
    }

    return result;
}

string JWE::getPlaintext() const
{
    return impl_->plaintext_;
}

string JWE::getHeader() const
{
    if (!impl_->header_json_.empty())
    {
        return impl_->header_json_;
    }

    json header = json::object();
    header["alg"] = JWA::toString(impl_->key_algorithm_);
    header["enc"] = JWA::toString(impl_->content_algorithm_);

    if (!impl_->typ_.empty())
    {
        header["typ"] = impl_->typ_;
    }

    if (!impl_->kid_.empty())
    {
        header["kid"] = impl_->kid_;
    }

    for (auto const &param : impl_->header_params_)
    {
        header[param.first] = param.second;
    }

    return header.dump();
}

}  // namespace JOSE
}  // namespace Vlinder
