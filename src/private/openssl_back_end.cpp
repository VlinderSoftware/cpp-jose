#include "openssl_back_end.hpp"

#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

using namespace std;

#ifndef JOSE_RSA_GENERATION_MAX_ATTEMPTS
#define JOSE_RSA_GENERATION_MAX_ATTEMPTS 8
#endif

static_assert(JOSE_RSA_GENERATION_MAX_ATTEMPTS > 0,
              "JOSE_RSA_GENERATION_MAX_ATTEMPTS must be greater than zero");

namespace Vlinder {
namespace JOSE {
namespace Private {

namespace {

template <typename T, typename Deleter>
auto makeOpenSSLGuard(T *ptr, Deleter deleter)
{
    return unique_ptr<T, Deleter>(ptr, deleter);
}

string getOpenSSLErrorString()
{
    unsigned long error = ERR_get_error();
    if (error == 0)
    {
        return "Unknown OpenSSL error";
    }

    char buffer[256] = {0};
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return buffer;
}

vector<unsigned char> toDERPublic(EVP_PKEY *pkey)
{
    int const size = i2d_PUBKEY(pkey, nullptr);
    if (size <= 0)
    {
        throw runtime_error("Failed to export public key");
    }

    vector<unsigned char> out(static_cast<size_t>(size));
    unsigned char *ptr = out.data();
    if (i2d_PUBKEY(pkey, &ptr) <= 0)
    {
        throw runtime_error("Failed to export public key");
    }

    return out;
}

vector<unsigned char> toDERPrivate(EVP_PKEY *pkey)
{
    int const size = i2d_PrivateKey(pkey, nullptr);
    if (size <= 0)
    {
        return {};
    }

    vector<unsigned char> out(static_cast<size_t>(size));
    unsigned char *ptr = out.data();
    if (i2d_PrivateKey(pkey, &ptr) <= 0)
    {
        throw runtime_error("Failed to export private key");
    }

    return out;
}

vector<unsigned char> bnToBytes(BIGNUM const *bn)
{
    if (bn == nullptr)
    {
        return {};
    }

    int const n = BN_num_bytes(bn);
    if (n <= 0)
    {
        return {};
    }

    vector<unsigned char> out(static_cast<size_t>(n));
    BN_bn2bin(bn, out.data());
    return out;
}

vector<unsigned char> bnToPaddedBytes(BIGNUM const *bn, size_t size)
{
    if (bn == nullptr)
    {
        return {};
    }

    vector<unsigned char> out(size, 0);
    if (BN_bn2binpad(bn, out.data(), static_cast<int>(size)) <= 0)
    {
        throw runtime_error("Failed to encode BIGNUM");
    }

    return out;
}

/// Convert a big-endian byte buffer (as produced by BN_bn2bin / BN_bn2binpad)
/// into the platform-native byte order required by OSSL_PARAM_construct_BN /
/// OSSL_PARAM_get_BN, which internally use BN_native2bn / BN_bn2nativepad.
/// On little-endian hosts (x86-64 / ARM LE) this reverses the bytes; on
/// big-endian hosts the result is identical to the input.
vector<unsigned char> bnBytesToNative(vector<unsigned char> const &big_endian)
{
    if (big_endian.empty())
    {
        return {};
    }
    auto bn = makeOpenSSLGuard(BN_bin2bn(big_endian.data(),
                                          static_cast<int>(big_endian.size()),
                                          nullptr),
                                [](BIGNUM *b)
                                {
                                    BN_free(b);
                                });
    if (bn == nullptr)
    {
        return {};
    }
    int const byte_count = BN_num_bytes(bn.get());
    if (byte_count <= 0)
    {
        return {};
    }
    vector<unsigned char> native(static_cast<size_t>(byte_count));
    BN_bn2nativepad(bn.get(), native.data(), static_cast<int>(native.size()));
    return native;
}

void appendDerLength(vector<unsigned char> &out, size_t length)
{
    if (length < 0x80)
    {
        out.push_back(static_cast<unsigned char>(length));
        return;
    }

    unsigned char encoded[sizeof(size_t)] = {};
    size_t count = 0;
    size_t value = length;
    while (value != 0)
    {
        encoded[count++] = static_cast<unsigned char>(value & 0xFF);
        value >>= 8;
    }

    out.push_back(static_cast<unsigned char>(0x80 | count));
    for (size_t i = 0; i < count; ++i)
    {
        out.push_back(encoded[count - 1 - i]);
    }
}

void appendDerInteger(vector<unsigned char> &out, vector<unsigned char> const &value)
{
    vector<unsigned char> normalized = value;
    while (normalized.size() > 1 && normalized[0] == 0)
    {
        normalized.erase(normalized.begin());
    }

    if (normalized.empty())
    {
        normalized.push_back(0);
    }

    if ((normalized[0] & 0x80) != 0)
    {
        normalized.insert(normalized.begin(), 0);
    }

    out.push_back(0x02);
    appendDerLength(out, normalized.size());
    out.insert(out.end(), normalized.begin(), normalized.end());
}

vector<unsigned char> buildRsaPrivateKeyPkcs1Der(vector<unsigned char> const &n_bytes,
                                                 vector<unsigned char> const &e_bytes,
                                                 vector<unsigned char> const &d_bytes,
                                                 vector<unsigned char> const &p_bytes,
                                                 vector<unsigned char> const &q_bytes,
                                                 vector<unsigned char> const &dp_bytes,
                                                 vector<unsigned char> const &dq_bytes,
                                                 vector<unsigned char> const &qi_bytes)
{
    if (n_bytes.empty() || e_bytes.empty() || d_bytes.empty() || p_bytes.empty() ||
        q_bytes.empty() || dp_bytes.empty() || dq_bytes.empty() || qi_bytes.empty())
    {
        return {};
    }

    vector<unsigned char> body;
    appendDerInteger(body, vector<unsigned char>{0});
    appendDerInteger(body, n_bytes);
    appendDerInteger(body, e_bytes);
    appendDerInteger(body, d_bytes);
    appendDerInteger(body, p_bytes);
    appendDerInteger(body, q_bytes);
    appendDerInteger(body, dp_bytes);
    appendDerInteger(body, dq_bytes);
    appendDerInteger(body, qi_bytes);

    vector<unsigned char> der;
    der.push_back(0x30);
    appendDerLength(der, body.size());
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

void resolveCurveNames(string const &curve,
                       string &canonical_curve,
                       string &openssl_curve_name,
                       size_t &coordinate_size)
{
    if (curve == "P-256" || curve == "prime256v1")
    {
        canonical_curve = "P-256";
        openssl_curve_name = "prime256v1";
        coordinate_size = 32;
        return;
    }
    if (curve == "P-384" || curve == "secp384r1")
    {
        canonical_curve = "P-384";
        openssl_curve_name = "secp384r1";
        coordinate_size = 48;
        return;
    }
    if (curve == "P-521" || curve == "secp521r1")
    {
        canonical_curve = "P-521";
        openssl_curve_name = "secp521r1";
        coordinate_size = 66;
        return;
    }

    throw runtime_error("Unsupported curve: " + curve);
}

void resolveOkpNames(Use use,
                     unsigned int bits,
                     string &curve_name,
                     string &openssl_name,
                     size_t &key_size)
{
    if (use == Use::signature)
    {
        if (bits >= 448)
        {
            curve_name = "Ed448";
            openssl_name = "ED448";
            key_size = 57;
        }
        else
        {
            curve_name = "Ed25519";
            openssl_name = "ED25519";
            key_size = 32;
        }
    }
    else
    {
        if (bits >= 448)
        {
            curve_name = "X448";
            openssl_name = "X448";
            key_size = 56;
        }
        else
        {
            curve_name = "X25519";
            openssl_name = "X25519";
            key_size = 32;
        }
    }
}

void resolveOkpFromCurve(string const &curve,
                         string &canonical_curve,
                         string &openssl_name,
                         size_t &key_size)
{
    if (curve == "Ed25519")
    {
        canonical_curve = "Ed25519";
        openssl_name = "ED25519";
        key_size = 32;
        return;
    }
    if (curve == "Ed448")
    {
        canonical_curve = "Ed448";
        openssl_name = "ED448";
        key_size = 57;
        return;
    }
    if (curve == "X25519")
    {
        canonical_curve = "X25519";
        openssl_name = "X25519";
        key_size = 32;
        return;
    }
    if (curve == "X448")
    {
        canonical_curve = "X448";
        openssl_name = "X448";
        key_size = 56;
        return;
    }

    throw runtime_error("Unsupported OKP curve: " + curve);
}

void extractRsaComponents(EVP_PKEY *pkey,
                          vector<unsigned char> &n_bytes,
                          vector<unsigned char> &e_bytes,
                          vector<unsigned char> &d_bytes,
                          vector<unsigned char> &p_bytes,
                          vector<unsigned char> &q_bytes,
                          vector<unsigned char> &dp_bytes,
                          vector<unsigned char> &dq_bytes,
                          vector<unsigned char> &qi_bytes)
{
    BIGNUM *n_raw = nullptr;
    BIGNUM *e_raw = nullptr;
    BIGNUM *d_raw = nullptr;
    BIGNUM *p_raw = nullptr;
    BIGNUM *q_raw = nullptr;
    BIGNUM *dp_raw = nullptr;
    BIGNUM *dq_raw = nullptr;
    BIGNUM *qi_raw = nullptr;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n_raw) <= 0 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e_raw) <= 0)
    {
        BN_free(n_raw);
        BN_free(e_raw);
        throw runtime_error("Failed to read RSA public parameters: " + getOpenSSLErrorString());
    }

    auto n = makeOpenSSLGuard(n_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });
    auto e = makeOpenSSLGuard(e_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qi_raw);

    auto d = makeOpenSSLGuard(d_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });
    auto p = makeOpenSSLGuard(p_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });
    auto q = makeOpenSSLGuard(q_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });
    auto dp = makeOpenSSLGuard(dp_raw,
                               [](BIGNUM *bn)
                               {
                                   BN_free(bn);
                               });
    auto dq = makeOpenSSLGuard(dq_raw,
                               [](BIGNUM *bn)
                               {
                                   BN_free(bn);
                               });
    auto qi = makeOpenSSLGuard(qi_raw,
                               [](BIGNUM *bn)
                               {
                                   BN_free(bn);
                               });

    n_bytes = bnToBytes(n.get());
    e_bytes = bnToBytes(e.get());
    d_bytes = bnToBytes(d.get());
    p_bytes = bnToBytes(p.get());
    q_bytes = bnToBytes(q.get());
    dp_bytes = bnToBytes(dp.get());
    dq_bytes = bnToBytes(dq.get());
    qi_bytes = bnToBytes(qi.get());
}

}  // namespace

OpenSSLRSAKey::OpenSSLRSAKey(vector<unsigned char> const &n,
                             vector<unsigned char> const &e,
                             vector<unsigned char> const &d,
                             vector<unsigned char> const &p,
                             vector<unsigned char> const &q,
                             vector<unsigned char> const &dp,
                             vector<unsigned char> const &dq,
                             vector<unsigned char> const &qi,
                             vector<unsigned char> const &public_blob,
                             vector<unsigned char> const &private_blob)
    : n_(n), e_(e), d_(d), p_(p), q_(q), dp_(dp), dq_(dq), qi_(qi), public_blob_(public_blob),
      private_blob_(private_blob)
{
}

vector<unsigned char> OpenSSLRSAKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> OpenSSLRSAKey::getPrivateBlob() const
{
    return private_blob_;
}

bool OpenSSLRSAKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Key> OpenSSLRSAKey::clone() const
{
    return make_unique<
        OpenSSLRSAKey>(n_, e_, d_, p_, q_, dp_, dq_, qi_, public_blob_, private_blob_);
}

vector<unsigned char> OpenSSLRSAKey::getN() const
{
    return n_;
}
vector<unsigned char> OpenSSLRSAKey::getE() const
{
    return e_;
}
vector<unsigned char> OpenSSLRSAKey::getD() const
{
    return d_;
}
vector<unsigned char> OpenSSLRSAKey::getP() const
{
    return p_;
}
vector<unsigned char> OpenSSLRSAKey::getQ() const
{
    return q_;
}
vector<unsigned char> OpenSSLRSAKey::getDp() const
{
    return dp_;
}
vector<unsigned char> OpenSSLRSAKey::getDq() const
{
    return dq_;
}
vector<unsigned char> OpenSSLRSAKey::getQi() const
{
    return qi_;
}

OpenSSLECKey::OpenSSLECKey(string const &curve_name,
                           vector<unsigned char> const &x,
                           vector<unsigned char> const &y,
                           vector<unsigned char> const &d,
                           vector<unsigned char> const &public_blob,
                           vector<unsigned char> const &private_blob)
    : ECKey(curve_name), x_(x), y_(y), d_(d), public_blob_(public_blob), private_blob_(private_blob)
{
}

vector<unsigned char> OpenSSLECKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> OpenSSLECKey::getPrivateBlob() const
{
    return private_blob_;
}

bool OpenSSLECKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Key> OpenSSLECKey::clone() const
{
    return make_unique<OpenSSLECKey>(getCurveName(), x_, y_, d_, public_blob_, private_blob_);
}

vector<unsigned char> OpenSSLECKey::getX() const
{
    return x_;
}
vector<unsigned char> OpenSSLECKey::getY() const
{
    return y_;
}
vector<unsigned char> OpenSSLECKey::getD() const
{
    return d_;
}

OpenSSLOKPKey::OpenSSLOKPKey(string const &curve_name,
                             vector<unsigned char> const &x,
                             vector<unsigned char> const &d,
                             vector<unsigned char> const &public_blob,
                             vector<unsigned char> const &private_blob)
    : OKPKey(curve_name), x_(x), d_(d), public_blob_(public_blob), private_blob_(private_blob)
{
}

vector<unsigned char> OpenSSLOKPKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> OpenSSLOKPKey::getPrivateBlob() const
{
    return private_blob_;
}

bool OpenSSLOKPKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Key> OpenSSLOKPKey::clone() const
{
    return make_unique<OpenSSLOKPKey>(getCurveName(), x_, d_, public_blob_, private_blob_);
}

vector<unsigned char> OpenSSLOKPKey::getX() const
{
    return x_;
}
vector<unsigned char> OpenSSLOKPKey::getD() const
{
    return d_;
}

unique_ptr<Key> OpenSSLBackEnd::generateRSA(unsigned int bits) const
{
    unsigned int const max_attempts = static_cast<unsigned int>(JOSE_RSA_GENERATION_MAX_ATTEMPTS);
    string last_reason;

    for (unsigned int attempt = 0; attempt < max_attempts; ++attempt)
    {
        auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                    [](EVP_PKEY_CTX *context)
                                    {
                                        EVP_PKEY_CTX_free(context);
                                    });
        if (ctx == nullptr)
        {
            throw runtime_error("Failed to create RSA context: " + getErrorString());
        }

        OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
                               OSSL_PARAM_construct_end()};

        EVP_PKEY *pkey_raw = nullptr;
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0 ||
            EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
        {
            throw runtime_error("Failed to generate RSA key: " + getErrorString());
        }
        auto pkey_guard = makeOpenSSLGuard(pkey_raw,
                                           [](EVP_PKEY *key)
                                           {
                                               EVP_PKEY_free(key);
                                           });

        vector<unsigned char> n_bytes;
        vector<unsigned char> e_bytes;
        vector<unsigned char> d_bytes;
        vector<unsigned char> p_bytes;
        vector<unsigned char> q_bytes;
        vector<unsigned char> dp_bytes;
        vector<unsigned char> dq_bytes;
        vector<unsigned char> qi_bytes;

        extractRsaComponents(pkey_guard.get(),
                             n_bytes,
                             e_bytes,
                             d_bytes,
                             p_bytes,
                             q_bytes,
                             dp_bytes,
                             dq_bytes,
                             qi_bytes);

        vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
        vector<unsigned char> private_blob = toDERPrivate(pkey_guard.get());

        bool const has_full_private = !d_bytes.empty() && !p_bytes.empty() && !q_bytes.empty() &&
                                      !dp_bytes.empty() && !dq_bytes.empty() && !qi_bytes.empty() &&
                                      !private_blob.empty();
        if (has_full_private)
        {
            return make_unique<OpenSSLRSAKey>(n_bytes,
                                              e_bytes,
                                              d_bytes,
                                              p_bytes,
                                              q_bytes,
                                              dp_bytes,
                                              dq_bytes,
                                              qi_bytes,
                                              public_blob,
                                              private_blob);
        }

        last_reason = "incomplete private RSA export from provider";
    }

    throw runtime_error("Failed to generate a complete RSA private key after " +
                        to_string(max_attempts) + " attempts: " + last_reason);
}

unique_ptr<Key> OpenSSLBackEnd::generateRSA(vector<unsigned char> const &n_bytes,
                                            vector<unsigned char> const &e_bytes,
                                            vector<unsigned char> const &d_bytes,
                                            vector<unsigned char> const &p_bytes,
                                            vector<unsigned char> const &q_bytes,
                                            vector<unsigned char> const &dp_bytes,
                                            vector<unsigned char> const &dq_bytes,
                                            vector<unsigned char> const &qi_bytes) const
{
    if (n_bytes.empty() || e_bytes.empty())
    {
        throw runtime_error("RSA import requires at least modulus (n) and public exponent (e)");
    }

    bool const has_any_private_input = !d_bytes.empty() || !p_bytes.empty() || !q_bytes.empty() ||
                                       !dp_bytes.empty() || !dq_bytes.empty() || !qi_bytes.empty();
    bool const has_d = !d_bytes.empty();
    bool const has_any_crt = !p_bytes.empty() || !q_bytes.empty() || !dp_bytes.empty() ||
                             !dq_bytes.empty() || !qi_bytes.empty();
    bool const has_full_crt = !p_bytes.empty() && !q_bytes.empty() && !dp_bytes.empty() &&
                              !dq_bytes.empty() && !qi_bytes.empty();

    vector<unsigned char> active_d_bytes(d_bytes);
    vector<unsigned char> active_p_bytes(p_bytes);
    vector<unsigned char> active_q_bytes(q_bytes);
    vector<unsigned char> active_dp_bytes(dp_bytes);
    vector<unsigned char> active_dq_bytes(dq_bytes);
    vector<unsigned char> active_qi_bytes(qi_bytes);
    vector<string> attempt_errors;

    auto try_import = [&](bool include_d,
                          bool include_primes,
                          bool include_crt_exponents,
                          bool include_qi,
                          int selection,
                          string const &attempt_label,
                          string &last_error) -> EVP_PKEY *
    {
        auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                    [](EVP_PKEY_CTX *context)
                                    {
                                        EVP_PKEY_CTX_free(context);
                                    });
        if (ctx == nullptr)
        {
            last_error = "Failed to create RSA import context";
            return nullptr;
        }

        if (EVP_PKEY_fromdata_init(ctx.get()) <= 0)
        {
            last_error = "Failed to initialize RSA import: " + getErrorString();
            return nullptr;
        }

        // OSSL_PARAM_get_BN / BN_native2bn expects native (platform) byte order,
        // but our component bytes are big-endian (from BN_bn2bin / JWK base64url).
        // Convert each component to native byte order before building the param array.
        auto n_native  = bnBytesToNative(n_bytes);
        auto e_native  = bnBytesToNative(e_bytes);
        auto d_native  = include_d              ? bnBytesToNative(active_d_bytes)  : vector<unsigned char>{};
        auto p_native  = include_primes         ? bnBytesToNative(active_p_bytes)  : vector<unsigned char>{};
        auto q_native  = include_primes         ? bnBytesToNative(active_q_bytes)  : vector<unsigned char>{};
        auto dp_native = include_crt_exponents  ? bnBytesToNative(active_dp_bytes) : vector<unsigned char>{};
        auto dq_native = include_crt_exponents  ? bnBytesToNative(active_dq_bytes) : vector<unsigned char>{};
        auto qi_native = include_qi             ? bnBytesToNative(active_qi_bytes) : vector<unsigned char>{};

        OSSL_PARAM params[9] = {OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end(),
                                OSSL_PARAM_construct_end()};

        size_t param_index = 0;
        params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                                        n_native.data(),
                                                        n_native.size());
        params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                                        e_native.data(),
                                                        e_native.size());

        if (include_d)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D,
                                        d_native.data(),
                                        d_native.size());
        }
        if (include_primes)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1,
                                        p_native.data(),
                                        p_native.size());
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2,
                                        q_native.data(),
                                        q_native.size());
        }
        if (include_crt_exponents)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                        dp_native.data(),
                                        dp_native.size());
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                        dq_native.data(),
                                        dq_native.size());
        }
        if (include_qi)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                        qi_native.data(),
                                        qi_native.size());
        }
        params[param_index] = OSSL_PARAM_construct_end();

        EVP_PKEY *candidate = nullptr;
        if (EVP_PKEY_fromdata(ctx.get(), &candidate, selection, params) <= 0)
        {
            last_error = "Failed RSA import attempt (" + attempt_label + "): " + getErrorString();
            attempt_errors.push_back(last_error);
            return nullptr;
        }
        return candidate;
    };

    EVP_PKEY *pkey = nullptr;
    string last_error;

    if (!has_any_private_input)
    {
        pkey =
            try_import(false, false, false, false, EVP_PKEY_PUBLIC_KEY, "public n/e", last_error);
    }
    else
    {
        if (!has_d)
        {
            throw runtime_error("RSA private key import requires parameter 'd'");
        }

        if (!has_any_crt)
        {
            pkey = try_import(true,
                              false,
                              false,
                              false,
                              EVP_PKEY_KEYPAIR,
                              "private n/e/d",
                              last_error);
        }
        else
        {
            if (!has_full_crt)
            {
                throw runtime_error("Ill-formed RSA private key: if any of p, q, dp, dq, qi are "
                                    "present, all must be present");
            }

            pkey = try_import(true,
                              true,
                              true,
                              true,
                              EVP_PKEY_KEYPAIR,
                              "full CRT n/e/d/p/q/dp/dq/qi",
                              last_error);

            if (pkey == nullptr)
            {
                // OpenSSL providers can reject otherwise-valid CRT tuples; retry without optional
                // CRT exponents.
                pkey = try_import(true,
                                  true,
                                  false,
                                  false,
                                  EVP_PKEY_KEYPAIR,
                                  "private minimum n/e/d/p/q",
                                  last_error);
            }

            if (pkey == nullptr)
            {
                // Final OpenSSL-provider compatibility fallback: import only n/e/d.
                pkey = try_import(true,
                                  false,
                                  false,
                                  false,
                                  EVP_PKEY_KEYPAIR,
                                  "private n/e/d fallback",
                                  last_error);
            }

            if (pkey == nullptr)
            {
                vector<unsigned char> der_private = buildRsaPrivateKeyPkcs1Der(n_bytes,
                                                                               e_bytes,
                                                                               active_d_bytes,
                                                                               active_p_bytes,
                                                                               active_q_bytes,
                                                                               active_dp_bytes,
                                                                               active_dq_bytes,
                                                                               active_qi_bytes);
                if (!der_private.empty())
                {
                    unsigned char const *der_ptr = der_private.data();
                    EVP_PKEY *der_candidate =
                        d2i_AutoPrivateKey(nullptr,
                                           &der_ptr,
                                           static_cast<long>(der_private.size()));
                    if (der_candidate != nullptr)
                    {
                        pkey = der_candidate;
                    }
                    else
                    {
                        last_error =
                            "Failed RSA import attempt (DER private fallback): " + getErrorString();
                        attempt_errors.push_back(last_error);
                    }
                }
            }
        }
    }

    if (pkey == nullptr)
    {
        if (!attempt_errors.empty())
        {
            string details;
            for (size_t index = 0; index < attempt_errors.size(); ++index)
            {
                if (index != 0)
                {
                    details += " | ";
                }
                details += attempt_errors[index];
            }
            throw runtime_error(details);
        }
        throw runtime_error(last_error.empty() ? "Failed to import RSA key" : last_error);
    }

    auto pkey_guard = makeOpenSSLGuard(pkey,
                                       [](EVP_PKEY *key)
                                       {
                                           EVP_PKEY_free(key);
                                       });

    vector<unsigned char> imported_n;
    vector<unsigned char> imported_e;
    vector<unsigned char> imported_d;
    vector<unsigned char> imported_p;
    vector<unsigned char> imported_q;
    vector<unsigned char> imported_dp;
    vector<unsigned char> imported_dq;
    vector<unsigned char> imported_qi;
    extractRsaComponents(pkey_guard.get(),
                         imported_n,
                         imported_e,
                         imported_d,
                         imported_p,
                         imported_q,
                         imported_dp,
                         imported_dq,
                         imported_qi);

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob =
        imported_d.empty() ? vector<unsigned char>{} : toDERPrivate(pkey_guard.get());

    return make_unique<OpenSSLRSAKey>(n_bytes,
                                      e_bytes,
                                      imported_d,
                                      imported_p,
                                      imported_q,
                                      imported_dp,
                                      imported_dq,
                                      imported_qi,
                                      public_blob,
                                      private_blob);
}

unique_ptr<Key> OpenSSLBackEnd::generateEC(string const &curve) const
{
    string canonical_curve;
    string openssl_curve_name;
    size_t coordinate_size = 0;
    resolveCurveNames(curve, canonical_curve, openssl_curve_name, coordinate_size);

    string group_name_param = openssl_curve_name;

    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create EC context: " + getErrorString());
    }

    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                            group_name_param.data(),
                                                            group_name_param.size() + 1),
                           OSSL_PARAM_construct_end()};

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0 ||
        EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        throw runtime_error("Failed to generate EC key: " + getErrorString());
    }
    auto pkey_guard = makeOpenSSLGuard(pkey_raw,
                                       [](EVP_PKEY *key)
                                       {
                                           EVP_PKEY_free(key);
                                       });

    BIGNUM *x_raw = nullptr;
    BIGNUM *y_raw = nullptr;
    BIGNUM *d_raw = nullptr;

    if (EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_EC_PUB_X, &x_raw) <= 0 ||
        EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &y_raw) <= 0)
    {
        throw runtime_error("Failed to read EC public coordinates: " + getErrorString());
    }

    auto x = makeOpenSSLGuard(x_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });
    auto y = makeOpenSSLGuard(y_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });

    EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_PRIV_KEY, &d_raw);
    auto d = makeOpenSSLGuard(d_raw,
                              [](BIGNUM *bn)
                              {
                                  BN_free(bn);
                              });

    vector<unsigned char> x_bytes = bnToPaddedBytes(x.get(), coordinate_size);
    vector<unsigned char> y_bytes = bnToPaddedBytes(y.get(), coordinate_size);
    vector<unsigned char> d_bytes =
        d == nullptr ? vector<unsigned char>{} : bnToPaddedBytes(d.get(), coordinate_size);

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob = toDERPrivate(pkey_guard.get());

    return make_unique<OpenSSLECKey>(canonical_curve,
                                     x_bytes,
                                     y_bytes,
                                     d_bytes,
                                     public_blob,
                                     private_blob);
}

unique_ptr<Key> OpenSSLBackEnd::generateEC(string const &curve,
                                           vector<unsigned char> const &x_bytes,
                                           vector<unsigned char> const &y_bytes,
                                           vector<unsigned char> const &d_bytes) const
{
    if (x_bytes.empty() || y_bytes.empty())
    {
        throw runtime_error("EC import requires both x and y coordinates");
    }

    string canonical_curve;
    string openssl_curve_name;
    size_t coordinate_size = 0;
    resolveCurveNames(curve, canonical_curve, openssl_curve_name, coordinate_size);

    string group_name_param = openssl_curve_name;

    if (x_bytes.size() != coordinate_size || y_bytes.size() != coordinate_size)
    {
        throw runtime_error("EC coordinate size does not match curve");
    }
    if (!d_bytes.empty() && d_bytes.size() != coordinate_size)
    {
        throw runtime_error("EC private scalar size does not match curve");
    }

    vector<unsigned char> public_point;
    public_point.reserve(1 + x_bytes.size() + y_bytes.size());
    public_point.push_back(0x04);
    public_point.insert(public_point.end(), x_bytes.begin(), x_bytes.end());
    public_point.insert(public_point.end(), y_bytes.begin(), y_bytes.end());

    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create EC import context: " + getErrorString());
    }

    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0)
    {
        throw runtime_error("Failed to initialize EC import: " + getErrorString());
    }

    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                            group_name_param.data(),
                                                            group_name_param.size() + 1),
                           OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                             public_point.data(),
                                                             public_point.size()),
                           OSSL_PARAM_construct_end()};

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey_raw, EVP_PKEY_PUBLIC_KEY, params) <= 0)
    {
        throw runtime_error("Failed to import EC key: " + getErrorString());
    }
    auto pkey_guard = makeOpenSSLGuard(pkey_raw,
                                       [](EVP_PKEY *key)
                                       {
                                           EVP_PKEY_free(key);
                                       });

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob;

    // When a private scalar is provided, build the full keypair EVP_PKEY so
    // we can derive and store the private DER blob.  This avoids falling back
    // to a component-based import (with its OSSL_PARAM endianness hazard) on
    // every subsequent sign operation.
    if (!d_bytes.empty())
    {
        auto d_native = bnBytesToNative(d_bytes);
        auto kp_ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                                        [](EVP_PKEY_CTX *c)
                                        {
                                            EVP_PKEY_CTX_free(c);
                                        });
        EVP_PKEY *kp_raw = nullptr;
        if (kp_ctx != nullptr && EVP_PKEY_fromdata_init(kp_ctx.get()) > 0)
        {
            OSSL_PARAM kp_params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 group_name_param.data(),
                                                 group_name_param.size() + 1),
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  public_point.data(),
                                                  public_point.size()),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                        d_native.data(),
                                        d_native.size()),
                OSSL_PARAM_construct_end()};
            if (EVP_PKEY_fromdata(kp_ctx.get(), &kp_raw, EVP_PKEY_KEYPAIR, kp_params) > 0)
            {
                auto kp_guard = makeOpenSSLGuard(kp_raw,
                                                 [](EVP_PKEY *k)
                                                 {
                                                     EVP_PKEY_free(k);
                                                 });
                private_blob = toDERPrivate(kp_guard.get());
            }
        }
    }

    return make_unique<OpenSSLECKey>(canonical_curve,
                                     x_bytes,
                                     y_bytes,
                                     d_bytes,
                                     public_blob,
                                     private_blob);
}

unique_ptr<Key> OpenSSLBackEnd::generateOct(unsigned int bits) const
{
    if (bits == 0 || (bits % 8) != 0)
    {
        throw runtime_error("Key size must be a non-zero multiple of 8 bits");
    }

    vector<unsigned char> key_bytes(bits / 8);
    if (RAND_bytes(key_bytes.data(), static_cast<int>(key_bytes.size())) != 1)
    {
        throw runtime_error("RAND_bytes failed: " + getErrorString());
    }

    return make_unique<OctKey>(key_bytes);
}

unique_ptr<Key> OpenSSLBackEnd::generateOct(unsigned int bits,
                                            vector<unsigned char> const &k_bytes) const
{
    if (k_bytes.size() != (bits / 8))
    {
        throw runtime_error("Key size error");
    }

    return make_unique<OctKey>(k_bytes);
}

unique_ptr<Key> OpenSSLBackEnd::generateOkp(Use use, unsigned int bits) const
{
    string curve_name;
    string openssl_name;
    size_t key_size = 0;
    resolveOkpNames(use, bits, curve_name, openssl_name, key_size);

    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, openssl_name.c_str(), nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create OKP context: " + getErrorString());
    }

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        throw runtime_error("Failed to generate OKP key: " + getErrorString());
    }
    auto pkey_guard = makeOpenSSLGuard(pkey_raw,
                                       [](EVP_PKEY *key)
                                       {
                                           EVP_PKEY_free(key);
                                       });

    vector<unsigned char> x_bytes(key_size);
    size_t x_len = x_bytes.size();
    if (EVP_PKEY_get_raw_public_key(pkey_guard.get(), x_bytes.data(), &x_len) != 1)
    {
        throw runtime_error("Failed to read OKP public key bytes: " + getErrorString());
    }
    x_bytes.resize(x_len);

    vector<unsigned char> d_bytes(key_size);
    size_t d_len = d_bytes.size();
    if (EVP_PKEY_get_raw_private_key(pkey_guard.get(), d_bytes.data(), &d_len) != 1)
    {
        throw runtime_error("Failed to read OKP private key bytes: " + getErrorString());
    }
    d_bytes.resize(d_len);

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob = toDERPrivate(pkey_guard.get());

    return make_unique<OpenSSLOKPKey>(curve_name, x_bytes, d_bytes, public_blob, private_blob);
}

unique_ptr<Key> OpenSSLBackEnd::generateOkp(string const &curve,
                                            vector<unsigned char> const &x_bytes,
                                            vector<unsigned char> const &d_bytes) const
{
    if (x_bytes.empty())
    {
        throw runtime_error("OKP import requires public key bytes (x)");
    }

    string canonical_curve;
    string openssl_name;
    size_t key_size = 0;
    resolveOkpFromCurve(curve, canonical_curve, openssl_name, key_size);

    if (x_bytes.size() != key_size)
    {
        throw runtime_error("OKP public key size does not match curve");
    }
    if (!d_bytes.empty() && d_bytes.size() != key_size)
    {
        throw runtime_error("OKP private key size does not match curve");
    }

    EVP_PKEY *pkey_raw = nullptr;
    if (!d_bytes.empty())
    {
        pkey_raw = EVP_PKEY_new_raw_private_key_ex(nullptr,
                                                   openssl_name.c_str(),
                                                   nullptr,
                                                   d_bytes.data(),
                                                   d_bytes.size());
    }
    else
    {
        pkey_raw = EVP_PKEY_new_raw_public_key_ex(nullptr,
                                                  openssl_name.c_str(),
                                                  nullptr,
                                                  x_bytes.data(),
                                                  x_bytes.size());
    }

    if (pkey_raw == nullptr)
    {
        throw runtime_error("Failed to import OKP key: " + getErrorString());
    }

    auto pkey_guard = makeOpenSSLGuard(pkey_raw,
                                       [](EVP_PKEY *key)
                                       {
                                           EVP_PKEY_free(key);
                                       });

    vector<unsigned char> actual_x(key_size);
    size_t x_len = actual_x.size();
    if (EVP_PKEY_get_raw_public_key(pkey_guard.get(), actual_x.data(), &x_len) != 1)
    {
        throw runtime_error("Failed to read imported OKP public bytes: " + getErrorString());
    }
    actual_x.resize(x_len);

    vector<unsigned char> actual_d;
    if (!d_bytes.empty())
    {
        actual_d.resize(key_size);
        size_t d_len = actual_d.size();
        if (EVP_PKEY_get_raw_private_key(pkey_guard.get(), actual_d.data(), &d_len) != 1)
        {
            throw runtime_error("Failed to read imported OKP private bytes: " + getErrorString());
        }
        actual_d.resize(d_len);
    }

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob =
        d_bytes.empty() ? vector<unsigned char>{} : toDERPrivate(pkey_guard.get());

    return make_unique<OpenSSLOKPKey>(canonical_curve,
                                      actual_x,
                                      actual_d,
                                      public_blob,
                                      private_blob);
}

vector<unsigned char> OpenSSLBackEnd::hash(HashAlgorithm algorithm,
                                           vector<unsigned char> const &data) const
{
    EVP_MD const *md = nullptr;
    switch (algorithm)
    {
        case HashAlgorithm::sha256:
            md = EVP_sha256();
            break;
        case HashAlgorithm::sha384:
            md = EVP_sha384();
            break;
        case HashAlgorithm::sha512:
            md = EVP_sha512();
            break;
        default:
            throw runtime_error("Unsupported hash algorithm");
    }

    auto ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                [](EVP_MD_CTX *md_ctx)
                                {
                                    EVP_MD_CTX_free(md_ctx);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("EVP_MD_CTX_new failed: " + getErrorString());
    }

    unsigned int out_size = EVP_MD_size(md);
    vector<unsigned char> digest(static_cast<size_t>(out_size));

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &out_size) != 1)
    {
        throw runtime_error("EVP digest failed: " + getErrorString());
    }

    digest.resize(out_size);
    return digest;
}

string OpenSSLBackEnd::base64Encode(vector<unsigned char> const &data) const
{
    if (data.empty())
    {
        return {};
    }

    size_t const encoded_size = 4 * ((data.size() + 2) / 3);
    vector<unsigned char> encoded(encoded_size + 1, 0);
    int const out_len = EVP_EncodeBlock(encoded.data(), data.data(), static_cast<int>(data.size()));
    if (out_len < 0)
    {
        throw runtime_error("EVP_EncodeBlock failed: " + getErrorString());
    }

    return string(reinterpret_cast<char const *>(encoded.data()), static_cast<size_t>(out_len));
}

vector<unsigned char> OpenSSLBackEnd::base64Decode(string const &encoded) const
{
    if (encoded.empty())
    {
        return {};
    }

    string cleaned;
    cleaned.reserve(encoded.size());
    for (unsigned char c : encoded)
    {
        if (c == '\r' || c == '\n')
        {
            continue;
        }
        cleaned.push_back(static_cast<char>(c));
    }

    if (cleaned.empty())
    {
        return {};
    }

    if ((cleaned.size() % 4) != 0)
    {
        throw runtime_error("Invalid base64 input length");
    }

    vector<unsigned char> decoded((cleaned.size() / 4) * 3);
    int out_len = EVP_DecodeBlock(decoded.data(),
                                  reinterpret_cast<unsigned char const *>(cleaned.data()),
                                  static_cast<int>(cleaned.size()));
    if (out_len < 0)
    {
        throw runtime_error("EVP_DecodeBlock failed: " + getErrorString());
    }

    size_t padding = 0;
    if (!cleaned.empty() && cleaned.back() == '=')
    {
        ++padding;
    }
    if (cleaned.size() > 1 && cleaned[cleaned.size() - 2] == '=')
    {
        ++padding;
    }

    decoded.resize(static_cast<size_t>(out_len) - padding);
    return decoded;
}

string OpenSSLBackEnd::getErrorString() const
{
    unsigned long const err = ERR_get_error();
    if (err == 0)
    {
        return "Unknown error";
    }

    char buffer[256] = {};
    ERR_error_string_n(err, buffer, sizeof(buffer));
    return string(buffer);
}

namespace {

EVP_MD const *getDigestAlgorithm(SignatureAlgorithm algorithm)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::ps256:
            return EVP_sha256();
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::ps384:
            return EVP_sha384();
        case SignatureAlgorithm::hs512:
        case SignatureAlgorithm::rs512:
        case SignatureAlgorithm::es512:
        case SignatureAlgorithm::ps512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

size_t getEcCoordinateSize(SignatureAlgorithm algorithm)
{
    switch (algorithm)
    {
        case SignatureAlgorithm::es256:
            return 32;
        case SignatureAlgorithm::es384:
            return 48;
        case SignatureAlgorithm::es512:
            return 66;
        default:
            throw runtime_error("Unsupported ECDSA algorithm");
    }
}

vector<unsigned char> getOctKeyBytes(Key *key)
{
    auto oct_key = dynamic_cast<OctKey *>(key);
    if (oct_key == nullptr)
    {
        throw runtime_error("Octet key required");
    }

    auto secret = oct_key->getK();
    if (secret.empty())
    {
        throw runtime_error("Octet key material is empty");
    }
    return secret;
}

EVP_PKEY *importRsaKey(RSAKey const &rsa_key, bool require_private)
{
    auto n_bytes = rsa_key.getN();
    auto e_bytes = rsa_key.getE();
    auto d_bytes = rsa_key.getD();

    if (n_bytes.empty() || e_bytes.empty())
    {
        throw runtime_error("RSA key is missing modulus or exponent");
    }
    if (require_private && d_bytes.empty())
    {
        throw runtime_error("RSA private key material is required");
    }

    // Prefer DER blob import. The blobs are serialised directly from a live
    // EVP_PKEY so they never suffer the CRT-consistency issues that arise when
    // EVP_PKEY_fromdata receives pre-computed CRT parameters whose ordering
    // may not match OpenSSL 3's internal expectations, causing lazy key
    // validation to fail with "bignum routines::no inverse" at sign/decrypt time.
    auto tryDerImport = [](vector<unsigned char> const &blob,
                           char const *structure,
                           int selection) -> EVP_PKEY *
    {
        if (blob.empty())
        {
            return nullptr;
        }
        EVP_PKEY *pkey = nullptr;
        unsigned char const *der_data = blob.data();
        size_t der_len = blob.size();
        auto dctx = makeOpenSSLGuard(
            OSSL_DECODER_CTX_new_for_pkey(
                &pkey, "DER", structure, "RSA", selection, nullptr, nullptr),
            [](OSSL_DECODER_CTX *ctx)
            {
                OSSL_DECODER_CTX_free(ctx);
            });
        if (dctx != nullptr &&
            OSSL_DECODER_from_data(dctx.get(), &der_data, &der_len) == 1 &&
            pkey != nullptr)
        {
            return pkey;
        }
        if (pkey != nullptr)
        {
            EVP_PKEY_free(pkey);
        }
        ERR_clear_error();
        return nullptr;
    };

    if (require_private)
    {
        EVP_PKEY *pkey =
            tryDerImport(rsa_key.getPrivateBlob(), "type-specific", EVP_PKEY_KEYPAIR);
        if (pkey != nullptr)
        {
            return pkey;
        }
    }
    else
    {
        EVP_PKEY *pkey =
            tryDerImport(rsa_key.getPublicBlob(), "SubjectPublicKeyInfo", EVP_PKEY_PUBLIC_KEY);
        if (pkey != nullptr)
        {
            return pkey;
        }
    }

    // Component-based fallback: supply only n/e/d — never CRT parameters.
    // Passing pre-computed p, q, dp, dq, qi to EVP_PKEY_fromdata can produce
    // a key object that OpenSSL 3 accepts at creation but rejects at first use
    // with "bignum routines::no inverse". With only n/e/d, OpenSSL owns all
    // internal CRT decisions and the key is always operationally consistent.
    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create RSA import context: " + getOpenSSLErrorString());
    }

    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0)
    {
        throw runtime_error("Failed to initialize RSA import: " + getOpenSSLErrorString());
    }

    // OSSL_PARAM_get_BN / BN_native2bn expects native (platform) byte order, but
    // our component bytes are big-endian.  Convert before building the param array.
    auto n_native = bnBytesToNative(n_bytes);
    auto e_native = bnBytesToNative(e_bytes);
    auto d_native = bnBytesToNative(d_bytes);  // empty when d_bytes is empty

    OSSL_PARAM params[4] = {OSSL_PARAM_construct_end(),
                            OSSL_PARAM_construct_end(),
                            OSSL_PARAM_construct_end(),
                            OSSL_PARAM_construct_end()};
    size_t param_index = 0;

    params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                                    n_native.data(),
                                                    n_native.size());
    params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                                    e_native.data(),
                                                    e_native.size());

    int selection = EVP_PKEY_PUBLIC_KEY;
    if (!d_native.empty())
    {
        selection = EVP_PKEY_KEYPAIR;
        params[param_index++] =
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D,
                                    d_native.data(),
                                    d_native.size());
    }
    params[param_index] = OSSL_PARAM_construct_end();

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey, selection, params) <= 0)
    {
        throw runtime_error("Failed to import RSA key: " + getOpenSSLErrorString());
    }
    return pkey;
}

EVP_PKEY *importEcKey(ECKey const &ec_key, bool require_private)
{
    string canonical_curve;
    string openssl_curve_name;
    size_t coordinate_size = 0;
    resolveCurveNames(ec_key.getCurveName(), canonical_curve, openssl_curve_name, coordinate_size);

    auto x_bytes = ec_key.getX();
    auto y_bytes = ec_key.getY();
    auto d_bytes = ec_key.getD();

    if (x_bytes.size() != coordinate_size || y_bytes.size() != coordinate_size)
    {
        throw runtime_error("EC key coordinates do not match curve size");
    }
    if (require_private && d_bytes.size() != coordinate_size)
    {
        throw runtime_error("EC private key material is required");
    }

    // Prefer DER blob import — avoids OSSL_PARAM_BN endianness issues entirely.
    auto tryDerImport = [](vector<unsigned char> const &blob,
                           char const *structure,
                           int selection) -> EVP_PKEY *
    {
        if (blob.empty())
        {
            return nullptr;
        }
        EVP_PKEY *pkey = nullptr;
        unsigned char const *der_data = blob.data();
        size_t der_len = blob.size();
        auto dctx = makeOpenSSLGuard(
            OSSL_DECODER_CTX_new_for_pkey(
                &pkey, "DER", structure, "EC", selection, nullptr, nullptr),
            [](OSSL_DECODER_CTX *ctx)
            {
                OSSL_DECODER_CTX_free(ctx);
            });
        if (dctx != nullptr &&
            OSSL_DECODER_from_data(dctx.get(), &der_data, &der_len) == 1 &&
            pkey != nullptr)
        {
            return pkey;
        }
        if (pkey != nullptr)
        {
            EVP_PKEY_free(pkey);
        }
        ERR_clear_error();
        return nullptr;
    };

    if (require_private)
    {
        EVP_PKEY *pkey =
            tryDerImport(ec_key.getPrivateBlob(), "type-specific", EVP_PKEY_KEYPAIR);
        if (pkey != nullptr)
        {
            return pkey;
        }
    }
    else
    {
        EVP_PKEY *pkey =
            tryDerImport(ec_key.getPublicBlob(), "SubjectPublicKeyInfo", EVP_PKEY_PUBLIC_KEY);
        if (pkey != nullptr)
        {
            return pkey;
        }
    }

    // Component-based fallback.
    // OSSL_PARAM_get_BN / BN_native2bn expects native (platform) byte order,
    // but our component bytes are big-endian.  Convert d before use.
    string group_name = openssl_curve_name;

    vector<unsigned char> public_point;
    public_point.reserve(1 + x_bytes.size() + y_bytes.size());
    public_point.push_back(0x04);
    public_point.insert(public_point.end(), x_bytes.begin(), x_bytes.end());
    public_point.insert(public_point.end(), y_bytes.begin(), y_bytes.end());

    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create EC import context: " + getOpenSSLErrorString());
    }

    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0)
    {
        throw runtime_error("Failed to initialize EC import: " + getOpenSSLErrorString());
    }

    EVP_PKEY *pkey = nullptr;
    if (require_private)
    {
        auto d_native = bnBytesToNative(d_bytes);
        OSSL_PARAM private_params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                             group_name.data(),
                                             group_name.size() + 1),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                              public_point.data(),
                                              public_point.size()),
            OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY,
                                    d_native.data(),
                                    d_native.size()),
            OSSL_PARAM_construct_end()};

        if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, private_params) <= 0)
        {
            throw runtime_error("Failed to import EC keypair: " + getOpenSSLErrorString());
        }
    }
    else
    {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                             group_name.data(),
                                             group_name.size() + 1),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                              public_point.data(),
                                              public_point.size()),
            OSSL_PARAM_construct_end()};

        if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        {
            throw runtime_error("Failed to import EC public key: " + getOpenSSLErrorString());
        }
    }

    return pkey;
}

EVP_PKEY *importOkpKey(OKPKey const &okp_key, bool require_private)
{
    string canonical_curve;
    string openssl_name;
    size_t key_size = 0;
    resolveOkpFromCurve(okp_key.getCurveName(), canonical_curve, openssl_name, key_size);

    auto x_bytes = okp_key.getX();
    auto d_bytes = okp_key.getD();

    if (x_bytes.size() != key_size)
    {
        throw runtime_error("OKP public key size does not match curve");
    }
    if (require_private && d_bytes.size() != key_size)
    {
        throw runtime_error("OKP private key material is required");
    }

    EVP_PKEY *pkey = nullptr;
    if (require_private)
    {
        pkey = EVP_PKEY_new_raw_private_key_ex(nullptr,
                                               openssl_name.c_str(),
                                               nullptr,
                                               d_bytes.data(),
                                               d_bytes.size());
    }
    else
    {
        pkey = EVP_PKEY_new_raw_public_key_ex(nullptr,
                                              openssl_name.c_str(),
                                              nullptr,
                                              x_bytes.data(),
                                              x_bytes.size());
    }

    if (pkey == nullptr)
    {
        throw runtime_error("Failed to import OKP key: " + getOpenSSLErrorString());
    }
    return pkey;
}

EVP_PKEY *importPkeyFromKey(Key *key, bool require_private)
{
    if (key == nullptr)
    {
        throw runtime_error("Key does not contain valid material");
    }

    if (auto rsa_key = dynamic_cast<RSAKey *>(key); rsa_key != nullptr)
    {
        return importRsaKey(*rsa_key, require_private);
    }
    if (auto ec_key = dynamic_cast<ECKey *>(key); ec_key != nullptr)
    {
        return importEcKey(*ec_key, require_private);
    }
    if (auto okp_key = dynamic_cast<OKPKey *>(key); okp_key != nullptr)
    {
        return importOkpKey(*okp_key, require_private);
    }

    throw runtime_error("Asymmetric key required");
}

vector<unsigned char> rsaEncrypt(EVP_PKEY *pkey,
                                 vector<unsigned char> const &plaintext,
                                 int padding,
                                 EVP_MD const *md = nullptr)
{
    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new(pkey, nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create RSA context: " + getOpenSSLErrorString());
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0)
    {
        throw runtime_error("Failed to initialize RSA encryption: " + getOpenSSLErrorString());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    {
        throw runtime_error("Failed to set RSA padding: " + getOpenSSLErrorString());
    }

    if (padding == RSA_PKCS1_OAEP_PADDING && md != nullptr)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md) <= 0)
        {
            throw runtime_error("Failed to configure RSA OAEP digest: " +
                                getOpenSSLErrorString());
        }
    }

    size_t output_size = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &output_size, plaintext.data(), plaintext.size()) <=
        0)
    {
        throw runtime_error("Failed to query RSA ciphertext size: " + getOpenSSLErrorString());
    }

    vector<unsigned char> ciphertext(output_size);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &output_size, plaintext.data(), plaintext.size()) <= 0)
    {
        throw runtime_error("RSA encryption failed: " + getOpenSSLErrorString());
    }

    ciphertext.resize(output_size);
    return ciphertext;
}

vector<unsigned char> rsaDecrypt(EVP_PKEY *pkey,
                                 vector<unsigned char> const &ciphertext,
                                 int padding,
                                 EVP_MD const *md = nullptr)
{
    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new(pkey, nullptr),
                                [](EVP_PKEY_CTX *context)
                                {
                                    EVP_PKEY_CTX_free(context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create RSA context: " + getOpenSSLErrorString());
    }

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0)
    {
        throw runtime_error("Failed to initialize RSA decryption: " + getOpenSSLErrorString());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), padding) <= 0)
    {
        throw runtime_error("Failed to set RSA padding: " + getOpenSSLErrorString());
    }
    if (padding == RSA_PKCS1_OAEP_PADDING && md != nullptr)
    {
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), md) <= 0)
        {
            throw runtime_error("Failed to configure RSA OAEP digest: " +
                                getOpenSSLErrorString());
        }
    }

    size_t output_size = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &output_size, ciphertext.data(), ciphertext.size()) <=
        0)
    {
        throw runtime_error("Failed to query RSA plaintext size: " + getOpenSSLErrorString());
    }

    vector<unsigned char> plaintext(output_size);
    if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &output_size, ciphertext.data(), ciphertext.size()) <= 0)
    {
        throw runtime_error("RSA decryption failed: " + getOpenSSLErrorString());
    }
    plaintext.resize(output_size);
    return plaintext;
}

vector<unsigned char> aesKeyWrap(vector<unsigned char> const &kek,
                                 vector<unsigned char> const &plaintext)
{
    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }

    EVP_CIPHER const *cipher = nullptr;
    if (kek.size() == 16)
    {
        cipher = EVP_aes_128_wrap();
    }
    else if (kek.size() == 24)
    {
        cipher = EVP_aes_192_wrap();
    }
    else if (kek.size() == 32)
    {
        cipher = EVP_aes_256_wrap();
    }
    else
    {
        throw runtime_error("Invalid AES key size for key wrap");
    }

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, kek.data(), nullptr) != 1)
    {
        throw runtime_error("Failed to initialize AES key wrap: " + getOpenSSLErrorString());
    }

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
    int output_size = 0;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &output_size, plaintext.data(), plaintext.size()) != 1)
    {
        throw runtime_error("AES key wrap failed: " + getOpenSSLErrorString());
    }

    int final_size = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + output_size, &final_size) != 1)
    {
        throw runtime_error("AES key wrap finalization failed: " + getOpenSSLErrorString());
    }

    ciphertext.resize(static_cast<size_t>(output_size + final_size));
    return ciphertext;
}

vector<unsigned char> aesKeyUnwrap(vector<unsigned char> const &kek,
                                   vector<unsigned char> const &ciphertext)
{
    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }

    EVP_CIPHER const *cipher = nullptr;
    if (kek.size() == 16)
    {
        cipher = EVP_aes_128_wrap();
    }
    else if (kek.size() == 24)
    {
        cipher = EVP_aes_192_wrap();
    }
    else if (kek.size() == 32)
    {
        cipher = EVP_aes_256_wrap();
    }
    else
    {
        throw runtime_error("Invalid AES key size for key unwrap");
    }

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, kek.data(), nullptr) != 1)
    {
        throw runtime_error("Failed to initialize AES key unwrap: " + getOpenSSLErrorString());
    }

    vector<unsigned char> plaintext(ciphertext.size());
    int output_size = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &output_size, ciphertext.data(), ciphertext.size()) != 1)
    {
        throw runtime_error("AES key unwrap failed: " + getOpenSSLErrorString());
    }

    int final_size = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + output_size, &final_size) != 1)
    {
        throw runtime_error("AES key unwrap finalization failed: " + getOpenSSLErrorString());
    }

    plaintext.resize(static_cast<size_t>(output_size + final_size));
    return plaintext;
}

pair<vector<unsigned char>, vector<unsigned char>> aesGcmEncrypt(EVP_CIPHER const *cipher,
                                                                  vector<unsigned char> const &cek,
                                                                  vector<unsigned char> const &iv,
                                                                  vector<unsigned char> const &plaintext,
                                                                  vector<unsigned char> const &aad)
{
    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }

    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        throw runtime_error("Failed to initialize AES-GCM encryption: " +
                            getOpenSSLErrorString());
    }

    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()) != 1)
    {
        throw runtime_error("Failed to process AAD: " + getOpenSSLErrorString());
    }

    vector<unsigned char> ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size()) !=
        1)
    {
        throw runtime_error("AES-GCM encryption failed: " + getOpenSSLErrorString());
    }

    int ciphertext_size = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1)
    {
        throw runtime_error("AES-GCM finalization failed: " + getOpenSSLErrorString());
    }
    ciphertext_size += len;
    ciphertext.resize(static_cast<size_t>(ciphertext_size));

    vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
    {
        throw runtime_error("Failed to extract AES-GCM authentication tag: " +
                            getOpenSSLErrorString());
    }

    return {ciphertext, tag};
}

vector<unsigned char> aesGcmDecrypt(EVP_CIPHER const *cipher,
                                    vector<unsigned char> const &cek,
                                    vector<unsigned char> const &iv,
                                    vector<unsigned char> const &ciphertext,
                                    vector<unsigned char> const &aad,
                                    vector<unsigned char> const &tag)
{
    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }

    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, cek.data(), iv.data()) != 1)
    {
        throw runtime_error("Failed to initialize AES-GCM decryption: " +
                            getOpenSSLErrorString());
    }

    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()) != 1)
    {
        throw runtime_error("Failed to process AAD: " + getOpenSSLErrorString());
    }

    vector<unsigned char> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size()) !=
        1)
    {
        throw runtime_error("AES-GCM decryption failed: " + getOpenSSLErrorString());
    }

    int plaintext_size = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(),
                            EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<unsigned char *>(tag.data())) != 1)
    {
        throw runtime_error("Failed to set AES-GCM authentication tag: " +
                            getOpenSSLErrorString());
    }

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1)
    {
        throw runtime_error("AES-GCM authentication failed: " + getOpenSSLErrorString());
    }
    plaintext_size += len;
    plaintext.resize(static_cast<size_t>(plaintext_size));
    return plaintext;
}

pair<vector<unsigned char>, vector<unsigned char>> aesCbcHmacEncrypt(EVP_CIPHER const *cipher,
                                                                      EVP_MD const *md,
                                                                      vector<unsigned char> const &cek,
                                                                      vector<unsigned char> const &iv,
                                                                      vector<unsigned char> const &plaintext,
                                                                      vector<unsigned char> const &aad)
{
    size_t const half = cek.size() / 2;
    vector<unsigned char> mac_key(cek.begin(), cek.begin() + static_cast<ptrdiff_t>(half));
    vector<unsigned char> enc_key(cek.begin() + static_cast<ptrdiff_t>(half), cek.end());

    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }
    if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, enc_key.data(), iv.data()) != 1)
    {
        throw runtime_error("Failed to initialize AES-CBC encryption: " +
                            getOpenSSLErrorString());
    }

    vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(cipher));
    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size()) !=
        1)
    {
        throw runtime_error("AES-CBC encryption failed: " + getOpenSSLErrorString());
    }

    int ciphertext_size = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1)
    {
        throw runtime_error("AES-CBC finalization failed: " + getOpenSSLErrorString());
    }
    ciphertext_size += len;
    ciphertext.resize(static_cast<size_t>(ciphertext_size));

    vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int index = 7; index >= 0; --index)
    {
        al[static_cast<size_t>(index)] = static_cast<unsigned char>(aad_bits & 0xFFU);
        aad_bits >>= 8;
    }

    vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    vector<unsigned char> mac(static_cast<size_t>(EVP_MD_size(md)));
    unsigned int mac_size = 0;
    if (HMAC(md,
             mac_key.data(),
             static_cast<int>(mac_key.size()),
             mac_data.data(),
             mac_data.size(),
             mac.data(),
             &mac_size) == nullptr)
    {
        throw runtime_error("HMAC computation failed: " + getOpenSSLErrorString());
    }
    (void)mac_size;

    vector<unsigned char> tag(mac.begin(), mac.begin() + static_cast<ptrdiff_t>(half));
    return {ciphertext, tag};
}

vector<unsigned char> aesCbcHmacDecrypt(EVP_CIPHER const *cipher,
                                        EVP_MD const *md,
                                        vector<unsigned char> const &cek,
                                        vector<unsigned char> const &iv,
                                        vector<unsigned char> const &ciphertext,
                                        vector<unsigned char> const &aad,
                                        vector<unsigned char> const &tag)
{
    size_t const half = cek.size() / 2;
    vector<unsigned char> mac_key(cek.begin(), cek.begin() + static_cast<ptrdiff_t>(half));
    vector<unsigned char> enc_key(cek.begin() + static_cast<ptrdiff_t>(half), cek.end());

    vector<unsigned char> al(8);
    size_t aad_bits = aad.size() * 8;
    for (int index = 7; index >= 0; --index)
    {
        al[static_cast<size_t>(index)] = static_cast<unsigned char>(aad_bits & 0xFFU);
        aad_bits >>= 8;
    }

    vector<unsigned char> mac_data;
    mac_data.insert(mac_data.end(), aad.begin(), aad.end());
    mac_data.insert(mac_data.end(), iv.begin(), iv.end());
    mac_data.insert(mac_data.end(), ciphertext.begin(), ciphertext.end());
    mac_data.insert(mac_data.end(), al.begin(), al.end());

    vector<unsigned char> mac(static_cast<size_t>(EVP_MD_size(md)));
    unsigned int mac_size = 0;
    if (HMAC(md,
             mac_key.data(),
             static_cast<int>(mac_key.size()),
             mac_data.data(),
             mac_data.size(),
             mac.data(),
             &mac_size) == nullptr)
    {
        throw runtime_error("HMAC computation failed: " + getOpenSSLErrorString());
    }
    (void)mac_size;

    vector<unsigned char> expected_tag(mac.begin(), mac.begin() + static_cast<ptrdiff_t>(half));
    if (expected_tag.size() != tag.size() ||
        CRYPTO_memcmp(expected_tag.data(), tag.data(), tag.size()) != 0)
    {
        throw runtime_error("Authentication tag verification failed");
    }

    auto ctx = makeOpenSSLGuard(EVP_CIPHER_CTX_new(),
                                [](EVP_CIPHER_CTX *cipher_context)
                                {
                                    EVP_CIPHER_CTX_free(cipher_context);
                                });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create cipher context: " + getOpenSSLErrorString());
    }
    if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, enc_key.data(), iv.data()) != 1)
    {
        throw runtime_error("Failed to initialize AES-CBC decryption: " +
                            getOpenSSLErrorString());
    }

    vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(cipher));
    int len = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size()) !=
        1)
    {
        throw runtime_error("AES-CBC decryption failed: " + getOpenSSLErrorString());
    }

    int plaintext_size = len;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1)
    {
        throw runtime_error("AES-CBC finalization failed: " + getOpenSSLErrorString());
    }

    plaintext_size += len;
    plaintext.resize(static_cast<size_t>(plaintext_size));
    return plaintext;
}

}  // namespace

vector<unsigned char> OpenSSLBackEnd::sign_(SignatureAlgorithm algorithm,
                                            Key *key,
                                            vector<unsigned char> const &data) const
{
    switch (algorithm)
    {
        case SignatureAlgorithm::none:
            return {};
        case SignatureAlgorithm::hs256:
        case SignatureAlgorithm::hs384:
        case SignatureAlgorithm::hs512:
        {
            auto md = getDigestAlgorithm(algorithm);
            auto secret = getOctKeyBytes(key);
            vector<unsigned char> signature(static_cast<size_t>(EVP_MD_size(md)));
            unsigned int signature_size = 0;
            if (HMAC(md,
                     secret.data(),
                     static_cast<int>(secret.size()),
                     data.data(),
                     data.size(),
                     signature.data(),
                     &signature_size) == nullptr)
            {
                throw runtime_error("HMAC signing failed: " + getOpenSSLErrorString());
            }
            signature.resize(signature_size);
            return signature;
        }
        case SignatureAlgorithm::rs256:
        case SignatureAlgorithm::rs384:
        case SignatureAlgorithm::rs512:
        case SignatureAlgorithm::ps256:
        case SignatureAlgorithm::ps384:
        case SignatureAlgorithm::ps512:
            return signRsa(algorithm, key, data);
        case SignatureAlgorithm::es256:
        case SignatureAlgorithm::es384:
        case SignatureAlgorithm::es512:
            return signEc(algorithm, key, data);
        default:
            throw runtime_error("Unsupported signature algorithm");
    }
}

bool OpenSSLBackEnd::verify_(SignatureAlgorithm algorithm,
                             Key *key,
                             std::vector<unsigned char> const &data,
                             std::vector<unsigned char> const &signature) const
{
    if (algorithm == SignatureAlgorithm::none)
    {
        return signature.empty();
    }

    if (algorithm == SignatureAlgorithm::hs256 || algorithm == SignatureAlgorithm::hs384 ||
        algorithm == SignatureAlgorithm::hs512)
    {
        auto expected = sign_(algorithm, key, data);
        if (expected.size() != signature.size())
        {
            return false;
        }
        return CRYPTO_memcmp(expected.data(), signature.data(), signature.size()) == 0;
    }

    if (algorithm == SignatureAlgorithm::rs256 || algorithm == SignatureAlgorithm::rs384 ||
        algorithm == SignatureAlgorithm::rs512 || algorithm == SignatureAlgorithm::ps256 ||
        algorithm == SignatureAlgorithm::ps384 || algorithm == SignatureAlgorithm::ps512)
    {
        auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, false),
                                     [](EVP_PKEY *imported)
                                     {
                                         EVP_PKEY_free(imported);
                                     });

        auto md_ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                       [](EVP_MD_CTX *context)
                                       {
                                           EVP_MD_CTX_free(context);
                                       });
        if (md_ctx == nullptr)
        {
            throw runtime_error("Failed to create digest context: " + getOpenSSLErrorString());
        }

        EVP_PKEY_CTX *key_ctx = nullptr;
        if (EVP_DigestVerifyInit(md_ctx.get(), &key_ctx, getDigestAlgorithm(algorithm), nullptr, pkey.get()) !=
            1)
        {
            throw runtime_error("Failed to initialize RSA verification: " +
                                getOpenSSLErrorString());
        }

        if (algorithm == SignatureAlgorithm::ps256 || algorithm == SignatureAlgorithm::ps384 ||
            algorithm == SignatureAlgorithm::ps512)
        {
            int salt_length = EVP_MD_size(getDigestAlgorithm(algorithm));
            if (EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, salt_length) <= 0)
            {
                throw runtime_error("Failed to configure RSA-PSS verification: " +
                                    getOpenSSLErrorString());
            }
        }

        int result = EVP_DigestVerify(md_ctx.get(),
                                      signature.data(),
                                      signature.size(),
                                      data.data(),
                                      data.size());
        return result == 1;
    }

    if (algorithm == SignatureAlgorithm::es256 || algorithm == SignatureAlgorithm::es384 ||
        algorithm == SignatureAlgorithm::es512)
    {
        size_t const coordinate_size = getEcCoordinateSize(algorithm);
        if (signature.size() != (2 * coordinate_size))
        {
            return false;
        }

        BIGNUM *r = BN_bin2bn(signature.data(), static_cast<int>(coordinate_size), nullptr);
        BIGNUM *s = BN_bin2bn(signature.data() + coordinate_size,
                              static_cast<int>(coordinate_size),
                              nullptr);
        if (r == nullptr || s == nullptr)
        {
            if (r != nullptr)
            {
                BN_free(r);
            }
            if (s != nullptr)
            {
                BN_free(s);
            }
            return false;
        }

        auto r_guard = makeOpenSSLGuard(r,
                                        [](BIGNUM *bn)
                                        {
                                            BN_free(bn);
                                        });
        auto s_guard = makeOpenSSLGuard(s,
                                        [](BIGNUM *bn)
                                        {
                                            BN_free(bn);
                                        });

        auto ecdsa_signature = makeOpenSSLGuard(ECDSA_SIG_new(),
                                                [](ECDSA_SIG *value)
                                                {
                                                    ECDSA_SIG_free(value);
                                                });
        if (ecdsa_signature == nullptr)
        {
            throw runtime_error("Failed to allocate ECDSA signature object");
        }

        if (ECDSA_SIG_set0(ecdsa_signature.get(), r_guard.release(), s_guard.release()) != 1)
        {
            throw runtime_error("Failed to assemble ECDSA signature");
        }

        unsigned char *der_buffer = nullptr;
        int der_size = i2d_ECDSA_SIG(ecdsa_signature.get(), &der_buffer);
        if (der_size <= 0)
        {
            throw runtime_error("Failed to encode ECDSA signature: " + getOpenSSLErrorString());
        }

        auto der_guard = makeOpenSSLGuard(der_buffer,
                                          [](unsigned char *buffer)
                                          {
                                              OPENSSL_free(buffer);
                                          });
        vector<unsigned char> der_signature(der_guard.get(),
                                            der_guard.get() + static_cast<ptrdiff_t>(der_size));

        auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, false),
                                     [](EVP_PKEY *imported)
                                     {
                                         EVP_PKEY_free(imported);
                                     });

        auto md_ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                       [](EVP_MD_CTX *context)
                                       {
                                           EVP_MD_CTX_free(context);
                                       });
        if (md_ctx == nullptr)
        {
            throw runtime_error("Failed to create digest context: " + getOpenSSLErrorString());
        }

        if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, getDigestAlgorithm(algorithm), nullptr, pkey.get()) != 1)
        {
            throw runtime_error("Failed to initialize ECDSA verification: " +
                                getOpenSSLErrorString());
        }

        int result = EVP_DigestVerify(md_ctx.get(),
                                      der_signature.data(),
                                      der_signature.size(),
                                      data.data(),
                                      data.size());
        return result == 1;
    }

    throw runtime_error("Unsupported signature algorithm");
}

vector<unsigned char> OpenSSLBackEnd::signRsa(SignatureAlgorithm algorithm,
                                              Key *key,
                                              vector<unsigned char> const &data) const
{
    auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                 [](EVP_PKEY *imported)
                                 {
                                     EVP_PKEY_free(imported);
                                 });

    auto md_ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                   [](EVP_MD_CTX *context)
                                   {
                                       EVP_MD_CTX_free(context);
                                   });
    if (md_ctx == nullptr)
    {
        throw runtime_error("Failed to create digest context: " + getOpenSSLErrorString());
    }

    EVP_PKEY_CTX *key_ctx = nullptr;
    if (EVP_DigestSignInit(md_ctx.get(), &key_ctx, getDigestAlgorithm(algorithm), nullptr, pkey.get()) !=
        1)
    {
        throw runtime_error("Failed to initialize RSA signing: " + getOpenSSLErrorString());
    }

    if (algorithm == SignatureAlgorithm::ps256 || algorithm == SignatureAlgorithm::ps384 ||
        algorithm == SignatureAlgorithm::ps512)
    {
        int salt_length = EVP_MD_size(getDigestAlgorithm(algorithm));
        if (EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, salt_length) <= 0)
        {
            throw runtime_error("Failed to configure RSA-PSS signing: " +
                                getOpenSSLErrorString());
        }
    }

    size_t signature_size = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &signature_size, data.data(), data.size()) != 1)
    {
        throw runtime_error("Failed to query RSA signature size: " + getOpenSSLErrorString());
    }

    vector<unsigned char> signature(signature_size);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &signature_size, data.data(), data.size()) !=
        1)
    {
        throw runtime_error("RSA signing failed: " + getOpenSSLErrorString());
    }

    signature.resize(signature_size);
    return signature;
}

vector<unsigned char> OpenSSLBackEnd::signEc(SignatureAlgorithm algorithm,
                                             Key *key,
                                             vector<unsigned char> const &data) const
{
    auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                 [](EVP_PKEY *imported)
                                 {
                                     EVP_PKEY_free(imported);
                                 });

    auto md_ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                   [](EVP_MD_CTX *context)
                                   {
                                       EVP_MD_CTX_free(context);
                                   });
    if (md_ctx == nullptr)
    {
        throw runtime_error("Failed to create digest context: " + getOpenSSLErrorString());
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, getDigestAlgorithm(algorithm), nullptr, pkey.get()) != 1)
    {
        throw runtime_error("Failed to initialize ECDSA signing: " + getOpenSSLErrorString());
    }

    size_t der_size = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &der_size, data.data(), data.size()) != 1)
    {
        throw runtime_error("Failed to query ECDSA signature size: " + getOpenSSLErrorString());
    }

    vector<unsigned char> der_signature(der_size);
    if (EVP_DigestSign(md_ctx.get(), der_signature.data(), &der_size, data.data(), data.size()) !=
        1)
    {
        throw runtime_error("ECDSA signing failed: " + getOpenSSLErrorString());
    }
    der_signature.resize(der_size);

    unsigned char const *input = der_signature.data();
    auto ecdsa_signature = makeOpenSSLGuard(d2i_ECDSA_SIG(nullptr,
                                                          &input,
                                                          static_cast<long>(der_signature.size())),
                                            [](ECDSA_SIG *value)
                                            {
                                                ECDSA_SIG_free(value);
                                            });
    if (ecdsa_signature == nullptr)
    {
        throw runtime_error("Failed to parse ECDSA signature: " + getOpenSSLErrorString());
    }

    BIGNUM const *r = nullptr;
    BIGNUM const *s = nullptr;
    ECDSA_SIG_get0(ecdsa_signature.get(), &r, &s);

    size_t const coordinate_size = getEcCoordinateSize(algorithm);
    vector<unsigned char> signature(2 * coordinate_size, 0);
    if (BN_bn2binpad(r, signature.data(), static_cast<int>(coordinate_size)) <= 0 ||
        BN_bn2binpad(s,
                     signature.data() + coordinate_size,
                     static_cast<int>(coordinate_size)) <= 0)
    {
        throw runtime_error("Failed to format ECDSA signature components");
    }

    return signature;
}

vector<unsigned char> OpenSSLBackEnd::signOkp(SignatureAlgorithm algorithm,
                                              Key *key,
                                              vector<unsigned char> const &data) const
{
    (void)algorithm;

    auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                 [](EVP_PKEY *imported)
                                 {
                                     EVP_PKEY_free(imported);
                                 });

    auto md_ctx = makeOpenSSLGuard(EVP_MD_CTX_new(),
                                   [](EVP_MD_CTX *context)
                                   {
                                       EVP_MD_CTX_free(context);
                                   });
    if (md_ctx == nullptr)
    {
        throw runtime_error("Failed to create digest context: " + getOpenSSLErrorString());
    }

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
    {
        throw runtime_error("Failed to initialize OKP signing: " + getOpenSSLErrorString());
    }

    size_t signature_size = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &signature_size, data.data(), data.size()) != 1)
    {
        throw runtime_error("Failed to query OKP signature size: " + getOpenSSLErrorString());
    }

    vector<unsigned char> signature(signature_size);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &signature_size, data.data(), data.size()) !=
        1)
    {
        throw runtime_error("OKP signing failed: " + getOpenSSLErrorString());
    }

    signature.resize(signature_size);
    return signature;
}

vector<unsigned char> OpenSSLBackEnd::encryptKey_(KeyEncryptionAlgorithm algorithm,
                                                  Key *key,
                                                  vector<unsigned char> const &cek,
                                                  optional<vector<unsigned char>> const &iv,
                                                  optional<vector<unsigned char>> const &tag,
                                                  Key *ephemeral_key,
                                                  ContentEncryptionAlgorithm content_alg) const
{
    (void)iv;
    (void)tag;
    (void)ephemeral_key;
    (void)content_alg;

    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::dir:
            return cek;
        case KeyEncryptionAlgorithm::rsa1_5:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, false),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaEncrypt(pkey.get(), cek, RSA_PKCS1_PADDING);
        }
        case KeyEncryptionAlgorithm::rsa_oaep:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, false),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaEncrypt(pkey.get(), cek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());
        }
        case KeyEncryptionAlgorithm::rsa_oaep_256:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, false),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaEncrypt(pkey.get(), cek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());
        }
        case KeyEncryptionAlgorithm::a128kw:
        case KeyEncryptionAlgorithm::a192kw:
        case KeyEncryptionAlgorithm::a256kw:
            return aesKeyWrap(getOctKeyBytes(key), cek);
        case KeyEncryptionAlgorithm::ecdh_es:
        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
            throw runtime_error("Key encryption algorithm is not implemented for OpenSSL backend");
        default:
            throw runtime_error("Unsupported key encryption algorithm");
    }
}

vector<unsigned char> OpenSSLBackEnd::decryptKey_(KeyEncryptionAlgorithm algorithm,
                                                  Key *key,
                                                  vector<unsigned char> const &encrypted_cek,
                                                  optional<vector<unsigned char>> const &iv,
                                                  optional<vector<unsigned char>> const &tag,
                                                  Key *ephemeral_key,
                                                  ContentEncryptionAlgorithm content_alg) const
{
    (void)iv;
    (void)tag;
    (void)ephemeral_key;
    (void)content_alg;

    switch (algorithm)
    {
        case KeyEncryptionAlgorithm::dir:
            return encrypted_cek;
        case KeyEncryptionAlgorithm::rsa1_5:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaDecrypt(pkey.get(), encrypted_cek, RSA_PKCS1_PADDING);
        }
        case KeyEncryptionAlgorithm::rsa_oaep:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaDecrypt(pkey.get(), encrypted_cek, RSA_PKCS1_OAEP_PADDING, EVP_sha1());
        }
        case KeyEncryptionAlgorithm::rsa_oaep_256:
        {
            auto pkey = makeOpenSSLGuard(importPkeyFromKey(key, true),
                                         [](EVP_PKEY *imported)
                                         {
                                             EVP_PKEY_free(imported);
                                         });
            return rsaDecrypt(pkey.get(), encrypted_cek, RSA_PKCS1_OAEP_PADDING, EVP_sha256());
        }
        case KeyEncryptionAlgorithm::a128kw:
        case KeyEncryptionAlgorithm::a192kw:
        case KeyEncryptionAlgorithm::a256kw:
            return aesKeyUnwrap(getOctKeyBytes(key), encrypted_cek);
        case KeyEncryptionAlgorithm::ecdh_es:
        case KeyEncryptionAlgorithm::a128gcmkw:
        case KeyEncryptionAlgorithm::a192gcmkw:
        case KeyEncryptionAlgorithm::a256gcmkw:
            throw runtime_error("Key decryption algorithm is not implemented for OpenSSL backend");
        default:
            throw runtime_error("Unsupported key decryption algorithm");
    }
}

pair<vector<unsigned char>, vector<unsigned char>>
OpenSSLBackEnd::encryptContent_(ContentEncryptionAlgorithm algorithm,
                                vector<unsigned char> const &cek,
                                vector<unsigned char> const &iv,
                                vector<unsigned char> const &plaintext,
                                vector<unsigned char> const &aad) const
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacEncrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacEncrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacEncrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a128gcm:
            return aesGcmEncrypt(EVP_aes_128_gcm(), cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a192gcm:
            return aesGcmEncrypt(EVP_aes_192_gcm(), cek, iv, plaintext, aad);
        case ContentEncryptionAlgorithm::a256gcm:
            return aesGcmEncrypt(EVP_aes_256_gcm(), cek, iv, plaintext, aad);
        default:
            throw runtime_error("Unsupported content encryption algorithm");
    }
}

vector<unsigned char> OpenSSLBackEnd::decryptContent_(ContentEncryptionAlgorithm algorithm,
                                                       vector<unsigned char> const &cek,
                                                       vector<unsigned char> const &iv,
                                                       vector<unsigned char> const &ciphertext,
                                                       vector<unsigned char> const &aad,
                                                       vector<unsigned char> const &tag) const
{
    switch (algorithm)
    {
        case ContentEncryptionAlgorithm::a128cbc_hs256:
            return aesCbcHmacDecrypt(EVP_aes_128_cbc(), EVP_sha256(), cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a192cbc_hs384:
            return aesCbcHmacDecrypt(EVP_aes_192_cbc(), EVP_sha384(), cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a256cbc_hs512:
            return aesCbcHmacDecrypt(EVP_aes_256_cbc(), EVP_sha512(), cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a128gcm:
            return aesGcmDecrypt(EVP_aes_128_gcm(), cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a192gcm:
            return aesGcmDecrypt(EVP_aes_192_gcm(), cek, iv, ciphertext, aad, tag);
        case ContentEncryptionAlgorithm::a256gcm:
            return aesGcmDecrypt(EVP_aes_256_gcm(), cek, iv, ciphertext, aad, tag);
        default:
            throw runtime_error("Unsupported content decryption algorithm");
    }
}

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
