#ifndef JOSE_JWA_HPP
#define JOSE_JWA_HPP

#include <optional>
#include <string>
#include <vector>

#include "jwk.hpp"

namespace Vlinder {
namespace JOSE {

/**
 * @brief JSON Web Algorithms (RFC 7518)
 *
 * Provides cryptographic operations for JOSE
 */
class JWA
{
public:
    /**
     * @brief Supported signature algorithms
     */
    enum class SignatureAlgorithm
    {
        hs256,  // HMAC using SHA-256
        hs384,  // HMAC using SHA-384
        hs512,  // HMAC using SHA-512
        rs256,  // RSASSA-PKCS1-v1_5 using SHA-256
        rs384,  // RSASSA-PKCS1-v1_5 using SHA-384
        rs512,  // RSASSA-PKCS1-v1_5 using SHA-512
        es256,  // ECDSA using P-256 and SHA-256
        es384,  // ECDSA using P-384 and SHA-384
        es512,  // ECDSA using P-521 and SHA-512
        ps256,  // RSASSA-PSS using SHA-256
        ps384,  // RSASSA-PSS using SHA-384
        ps512,  // RSASSA-PSS using SHA-512
        none    // No signature
    };

    /**
     * @brief Supported key encryption algorithms
     */
    enum class KeyEncryptionAlgorithm
    {
        rsa1_5,        // RSAES-PKCS1-v1_5
        rsa_oaep,      // RSAES OAEP using default parameters
        rsa_oaep_256,  // RSAES OAEP using SHA-256 and MGF1 with SHA-256
        a128kw,        // AES Key Wrap with default initial value using 128-bit key
        a192kw,        // AES Key Wrap with default initial value using 192-bit key
        a256kw,        // AES Key Wrap with default initial value using 256-bit key
        dir,           // Direct use of a shared symmetric key
        ecdh_es,       // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement
        a128gcmkw,     // Key wrapping with AES GCM using 128-bit key
        a192gcmkw,     // Key wrapping with AES GCM using 192-bit key
        a256gcmkw      // Key wrapping with AES GCM using 256-bit key
    };

    /**
     * @brief Supported content encryption algorithms
     */
    enum class ContentEncryptionAlgorithm
    {
        a128cbc_hs256,  // AES_128_CBC_HMAC_SHA_256
        a192cbc_hs384,  // AES_192_CBC_HMAC_SHA_384
        a256cbc_hs512,  // AES_256_CBC_HMAC_SHA_512
        a128gcm,        // AES GCM using 128-bit key
        a192gcm,        // AES GCM using 192-bit key
        a256gcm         // AES GCM using 256-bit key
    };

    /**
     * @brief Verify signature
     * @param algorithm Signature algorithm
     * @param key Key to use for verification
     * @param data Original data
     * @param signature Signature to verify
     * @return true if valid, false otherwise
     */
    static bool verify(SignatureAlgorithm algorithm,
                       const JWK &key,
                       std::vector<unsigned char> const &data,
                       std::vector<unsigned char> const &signature);  // TODO should be a JWS

    /**
     * @brief Encrypt content encryption key
     * @param algorithm Key encryption algorithm
     * @param key Key encryption key
     * @param cek Content encryption key to encrypt
     * @param iv Output parameter for IV (used by AES-GCM key wrap)
     * @param tag Output parameter for authentication tag (used by AES-GCM key wrap)
     * @param ephemeralKey Output parameter for ephemeral key (used by ECDH-ES)
     * @param contentAlg Content encryption algorithm (for ECDH-ES key derivation)
     * @return Encrypted CEK
     */
    // TODO most of the output parameters should be in the return value, which should be a JWE
    static std::vector<unsigned char>
    encryptKey(KeyEncryptionAlgorithm algorithm,
               const JWK &key,
               std::vector<unsigned char> const &cek,
               std::optional<std::vector<unsigned char>> const &iv = {},
               std::optional<std::vector<unsigned char>> const &tag = {},
               std::optional<JWK> const &ephemeral_key = {},
               ContentEncryptionAlgorithm content_alg = ContentEncryptionAlgorithm::a128gcm);

    /**
     * @brief Decrypt content encryption key
     * @param algorithm Key encryption algorithm
     * @param key Key encryption key
     * @param encryptedCek Encrypted CEK
     * @param iv Input parameter for IV (used by AES-GCM key wrap)
     * @param tag Input parameter for authentication tag (used by AES-GCM key wrap)
     * @param ephemeralKey Input parameter for ephemeral key (used by ECDH-ES)
     * @param contentAlg Content encryption algorithm (for ECDH-ES key derivation)
     * @return Decrypted CEK
     */
    // TODO most of the input parmaeters should be a JWE, and the return value should be a JWK
    static std::vector<unsigned char>
    decryptKey(KeyEncryptionAlgorithm algorithm,
               JWK const &key,
               std::vector<unsigned char> const &encrypted_cek,
               std::optional<std::vector<unsigned char>> const &iv = {},
               std::optional<std::vector<unsigned char>> const &tag = {},
               std::optional<JWK> const &ephemeral_key = {},
               ContentEncryptionAlgorithm content_alg = ContentEncryptionAlgorithm::a128gcm);

    /**
     * @brief Encrypt content
     * @param algorithm Content encryption algorithm
     * @param cek Content encryption key
     * @param iv Initialization vector
     * @param plaintext Plaintext to encrypt
     * @param aad Additional authenticated data
     * @return Ciphertext and authentication tag
     */
    static std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
    encryptContent(ContentEncryptionAlgorithm algorithm,
                   std::vector<unsigned char> const &cek,
                   std::vector<unsigned char> const &iv,
                   std::vector<unsigned char> const &plaintext,
                   std::vector<unsigned char> const &aad);

    /**
     * @brief Decrypt content
     * @param algorithm Content encryption algorithm
     * @param cek Content encryption key
     * @param iv Initialization vector
     * @param ciphertext Ciphertext to decrypt
     * @param aad Additional authenticated data
     * @param tag Authentication tag
     * @return Decrypted plaintext
     */
    static std::vector<unsigned char> decryptContent(ContentEncryptionAlgorithm algorithm,
                                                     std::vector<unsigned char> const &cek,
                                                     std::vector<unsigned char> const &iv,
                                                     std::vector<unsigned char> const &ciphertext,
                                                     std::vector<unsigned char> const &aad,
                                                     std::vector<unsigned char> const &tag);

    /**
     * @brief Convert algorithm enum to string
     */
    static std::string toString(SignatureAlgorithm alg);
    static std::string toString(KeyEncryptionAlgorithm alg);
    static std::string toString(ContentEncryptionAlgorithm alg);

    /**
     * @brief Convert string to algorithm enum
     */
    static SignatureAlgorithm signatureAlgorithmFromString(std::string const &alg);
    static KeyEncryptionAlgorithm keyEncryptionAlgorithmFromString(std::string const &alg);
    static ContentEncryptionAlgorithm contentEncryptionAlgorithmFromString(std::string const &alg);
};

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JWA_HPP
