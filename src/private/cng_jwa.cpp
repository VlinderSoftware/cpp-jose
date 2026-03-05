#include "jwa.hpp"

#include <stdexcept>

#if defined(JOSE_USE_CNG)

using namespace std;

namespace Vlinder {
namespace JOSE {

vector<unsigned char> JWA::sign(SignatureAlgorithm algorithm, JWK const &key, vector<unsigned char> const &data)
{
    (void)algorithm;
    (void)key;
    (void)data;
    throw runtime_error("JWA sign is not implemented for CNG back-end yet");
}

bool JWA::verify(SignatureAlgorithm algorithm, JWK const &key, vector<unsigned char> const &data, vector<unsigned char> const &signature)
{
    (void)algorithm;
    (void)key;
    (void)data;
    (void)signature;
    throw runtime_error("JWA verify is not implemented for CNG back-end yet");
}

vector<unsigned char> JWA::encryptKey(KeyEncryptionAlgorithm algorithm, const JWK& key,
                                           const vector<unsigned char>& cek,
                                           vector<unsigned char>* out_iv,
                                           vector<unsigned char>* out_tag,
                                           JWK* ephemeral_key,
                                           ContentEncryptionAlgorithm content_alg)
{
    (void)algorithm;
    (void)key;
    (void)cek;
    (void)out_iv;
    (void)out_tag;
    (void)ephemeral_key;
    (void)content_alg;
    throw runtime_error("JWA key encryption is not implemented for CNG back-end yet");
}

vector<unsigned char> JWA::decryptKey(KeyEncryptionAlgorithm algorithm, const JWK& key,
                                           const vector<unsigned char>& encrypted_cek,
                                           const vector<unsigned char>* in_iv,
                                           const vector<unsigned char>* in_tag,
                                           const JWK* ephemeral_key,
                                           ContentEncryptionAlgorithm content_alg)
{
    (void)algorithm;
    (void)key;
    (void)encrypted_cek;
    (void)in_iv;
    (void)in_tag;
    (void)ephemeral_key;
    (void)content_alg;
    throw runtime_error("JWA key decryption is not implemented for CNG back-end yet");
}

pair<vector<unsigned char>, vector<unsigned char>>
JWA::encryptContent(ContentEncryptionAlgorithm algorithm, const vector<unsigned char>& cek,
                    const vector<unsigned char>& iv,
                    const vector<unsigned char>& plaintext,
                    const vector<unsigned char>& aad)
{
    (void)algorithm;
    (void)cek;
    (void)iv;
    (void)plaintext;
    (void)aad;
    throw runtime_error("JWA content encryption is not implemented for CNG back-end yet");
}

vector<unsigned char> JWA::decryptContent(ContentEncryptionAlgorithm algorithm,
                                               const vector<unsigned char>& cek,
                                               const vector<unsigned char>& iv,
                                               const vector<unsigned char>& ciphertext,
                                               const vector<unsigned char>& aad,
                                               const vector<unsigned char>& tag)
{
    (void)algorithm;
    (void)cek;
    (void)iv;
    (void)ciphertext;
    (void)aad;
    (void)tag;
    throw runtime_error("JWA content decryption is not implemented for CNG back-end yet");
}

}  // namespace JOSE
}  // namespace Vlinder

#endif
