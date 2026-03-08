#include "openssl_back_end.hpp"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

using namespace std;

namespace Vlinder {
namespace JOSE {
namespace Private {

namespace {

template< typename T, typename Deleter >
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
    if (n_bytes.empty() || e_bytes.empty() || d_bytes.empty() || p_bytes.empty() || q_bytes.empty() ||
        dp_bytes.empty() || dq_bytes.empty() || qi_bytes.empty())
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

    auto n = makeOpenSSLGuard(n_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto e = makeOpenSSLGuard(e_raw, [](BIGNUM *bn) { BN_free(bn); });

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq_raw);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qi_raw);

    auto d = makeOpenSSLGuard(d_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto p = makeOpenSSLGuard(p_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto q = makeOpenSSLGuard(q_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto dp = makeOpenSSLGuard(dp_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto dq = makeOpenSSLGuard(dq_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto qi = makeOpenSSLGuard(qi_raw, [](BIGNUM *bn) { BN_free(bn); });

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
    auto ctx = makeOpenSSLGuard(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                [](EVP_PKEY_CTX *context) { EVP_PKEY_CTX_free(context); });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create RSA context: " + getErrorString());
    }

    OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
                           OSSL_PARAM_construct_end()};

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0 ||
        EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        throw runtime_error("Failed to generate RSA key: " + getErrorString());
    }
    auto pkey_guard = makeOpenSSLGuard(pkey_raw, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

    vector<unsigned char> n_bytes;
    vector<unsigned char> e_bytes;
    vector<unsigned char> d_bytes;
    vector<unsigned char> p_bytes;
    vector<unsigned char> q_bytes;
    vector<unsigned char> dp_bytes;
    vector<unsigned char> dq_bytes;
    vector<unsigned char> qi_bytes;

    extractRsaComponents(
        pkey_guard.get(), n_bytes, e_bytes, d_bytes, p_bytes, q_bytes, dp_bytes, dq_bytes, qi_bytes);

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob = toDERPrivate(pkey_guard.get());

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
                                    [](EVP_PKEY_CTX *context) { EVP_PKEY_CTX_free(context); });
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
                                                        const_cast<unsigned char *>(n_bytes.data()),
                                                        n_bytes.size());
        params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                                        const_cast<unsigned char *>(e_bytes.data()),
                                                        e_bytes.size());

        if (include_d)
        {
            params[param_index++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D,
                                                            const_cast<unsigned char *>(active_d_bytes.data()),
                                                            active_d_bytes.size());
        }
        if (include_primes)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1,
                                        const_cast<unsigned char *>(active_p_bytes.data()),
                                        active_p_bytes.size());
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2,
                                        const_cast<unsigned char *>(active_q_bytes.data()),
                                        active_q_bytes.size());
        }
        if (include_crt_exponents)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                        const_cast<unsigned char *>(active_dp_bytes.data()),
                                        active_dp_bytes.size());
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                        const_cast<unsigned char *>(active_dq_bytes.data()),
                                        active_dq_bytes.size());
        }
        if (include_qi)
        {
            params[param_index++] =
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                        const_cast<unsigned char *>(active_qi_bytes.data()),
                                        active_qi_bytes.size());
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
        pkey = try_import(false,
                          false,
                          false,
                          false,
                          EVP_PKEY_PUBLIC_KEY,
                          "public n/e",
                          last_error);
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
                throw runtime_error(
                    "Ill-formed RSA private key: if any of p, q, dp, dq, qi are present, all must be present");
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
                // OpenSSL providers can reject otherwise-valid CRT tuples; retry without optional CRT exponents.
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
                        d2i_AutoPrivateKey(nullptr, &der_ptr, static_cast<long>(der_private.size()));
                    if (der_candidate != nullptr)
                    {
                        pkey = der_candidate;
                    }
                    else
                    {
                        last_error = "Failed RSA import attempt (DER private fallback): " + getErrorString();
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

    auto pkey_guard = makeOpenSSLGuard(pkey, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

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
                                [](EVP_PKEY_CTX *context) { EVP_PKEY_CTX_free(context); });
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
    auto pkey_guard = makeOpenSSLGuard(pkey_raw, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

    BIGNUM *x_raw = nullptr;
    BIGNUM *y_raw = nullptr;
    BIGNUM *d_raw = nullptr;

    if (EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_EC_PUB_X, &x_raw) <= 0 ||
        EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &y_raw) <= 0)
    {
        throw runtime_error("Failed to read EC public coordinates: " + getErrorString());
    }

    auto x = makeOpenSSLGuard(x_raw, [](BIGNUM *bn) { BN_free(bn); });
    auto y = makeOpenSSLGuard(y_raw, [](BIGNUM *bn) { BN_free(bn); });

    EVP_PKEY_get_bn_param(pkey_guard.get(), OSSL_PKEY_PARAM_PRIV_KEY, &d_raw);
    auto d = makeOpenSSLGuard(d_raw, [](BIGNUM *bn) { BN_free(bn); });

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
                                [](EVP_PKEY_CTX *context) { EVP_PKEY_CTX_free(context); });
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
    auto pkey_guard = makeOpenSSLGuard(pkey_raw, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

    vector<unsigned char> public_blob = toDERPublic(pkey_guard.get());
    vector<unsigned char> private_blob;

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
                                [](EVP_PKEY_CTX *context) { EVP_PKEY_CTX_free(context); });
    if (ctx == nullptr)
    {
        throw runtime_error("Failed to create OKP context: " + getErrorString());
    }

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0)
    {
        throw runtime_error("Failed to generate OKP key: " + getErrorString());
    }
    auto pkey_guard = makeOpenSSLGuard(pkey_raw, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

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

    auto pkey_guard = makeOpenSSLGuard(pkey_raw, [](EVP_PKEY *key) { EVP_PKEY_free(key); });

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

    auto ctx = makeOpenSSLGuard(EVP_MD_CTX_new(), [](EVP_MD_CTX *md_ctx) { EVP_MD_CTX_free(md_ctx); });
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

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
