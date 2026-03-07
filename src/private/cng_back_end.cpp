#include "cng_back_end.hpp"

#include <wincrypt.h>

#include <algorithm>
#include <stdexcept>

using namespace std;

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace Vlinder {
namespace JOSE {
namespace Private {

CNGRSAKey::CNGRSAKey(vector<unsigned char> n,
                     vector<unsigned char> e,
                     vector<unsigned char> d,
                     vector<unsigned char> p,
                     vector<unsigned char> q,
                     vector<unsigned char> dp,
                     vector<unsigned char> dq,
                     vector<unsigned char> iqmp,
                     vector<unsigned char> public_blob,
                     vector<unsigned char> private_blob,
                     BCRYPT_KEY_HANDLE key_handle /* = nullptr*/,
                     BCRYPT_ALG_HANDLE alg_handle /* = nullptr*/)
    : public_blob_(std::move(public_blob)), private_blob_(std::move(private_blob)),
      n_(std::move(n)), e_(std::move(e)), d_(std::move(d)), p_(std::move(p)), q_(std::move(q)),
      dp_(std::move(dp)), dq_(std::move(dq)), iqmp_(std::move(iqmp)), key_handle_(key_handle),
      alg_handle_(alg_handle)
{
}

vector<unsigned char> CNGRSAKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> CNGRSAKey::getPrivateBlob() const
{
    return private_blob_;
}

bool CNGRSAKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Private::Key> CNGRSAKey::clone() const
{
    // CNG handles are not duplicable; the clone carries only the serialisable fields.
    return make_unique<CNGRSAKey>(n_, e_, d_, p_, q_, dp_, dq_, iqmp_, public_blob_, private_blob_);
}

// CNGECKey implementation
CNGECKey::CNGECKey(string curve_name,
                   vector<unsigned char> const &x,
                   vector<unsigned char> const &y,
                   vector<unsigned char> const &d,
                   vector<unsigned char> public_blob,
                   vector<unsigned char> private_blob,
                   BCRYPT_KEY_HANDLE key_handle,
                   BCRYPT_ALG_HANDLE alg_handle)
    : ECKey(curve_name), x_(x), y_(y), d_(d), public_blob_(std::move(public_blob)),
      private_blob_(std::move(private_blob)), key_handle_(key_handle), alg_handle_(alg_handle)
{
}

vector<unsigned char> CNGECKey::getPublicBlob() const
{
    return public_blob_;
}

vector<unsigned char> CNGECKey::getPrivateBlob() const
{
    return private_blob_;
}

bool CNGECKey::hasPrivate() const
{
    return !d_.empty() || !private_blob_.empty();
}

unique_ptr<Private::Key> CNGECKey::clone() const
{
    // CNG handles are not duplicable; the clone carries only the serialisable fields.
    return make_unique<CNGECKey>(getCurveName(), x_, y_, d_, public_blob_, private_blob_);
}

// CNGRSAKey parameter accessors
vector<unsigned char> CNGRSAKey::getN() const
{
    return n_;
}
vector<unsigned char> CNGRSAKey::getE() const
{
    return e_;
}
vector<unsigned char> CNGRSAKey::getD() const
{
    return d_;
}
vector<unsigned char> CNGRSAKey::getP() const
{
    return p_;
}
vector<unsigned char> CNGRSAKey::getQ() const
{
    return q_;
}
vector<unsigned char> CNGRSAKey::getDp() const
{
    return dp_;
}
vector<unsigned char> CNGRSAKey::getDq() const
{
    return dq_;
}
vector<unsigned char> CNGRSAKey::getQi() const
{
    return iqmp_;
}

unique_ptr<Key> CNGBackEnd::generateRSA(unsigned int bits) const
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateKeyPair(alg_guard.get(), &hKey, bits, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    status = BCryptFinalizeKeyPair(key_guard.get(), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinalizeKeyPair failed: " + getErrorString());
    }

    // Export public key
    ULONG pub_size = 0;
    status =
        BCryptExportKey(key_guard.get(), nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pub_size, 0);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    vector<unsigned char> pub_blob(pub_size);
    ULONG pub_blob_size = static_cast<ULONG>(pub_blob.size());
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_RSAPUBLIC_BLOB,
                             pub_blob.data(),
                             pub_blob_size,
                             &pub_size,
                             0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    // Parse public blob for n and e
    vector<unsigned char> n, e;
    if (pub_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
    {
        BCRYPT_RSAKEY_BLOB header{};
        copy_n(pub_blob.data(), sizeof(header), reinterpret_cast<unsigned char *>(&header));

        // Verify the blob is large enough to hold all fields described by the header
        size_t const expected_pub_size =
            sizeof(BCRYPT_RSAKEY_BLOB) + header.cbPublicExp + header.cbModulus;
        if (pub_blob.size() < expected_pub_size)
        {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw runtime_error("BCryptExportKey returned a truncated public blob");
        }

        unsigned char const *ptr = pub_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        if (header.cbPublicExp)
        {
            e.assign(ptr, ptr + header.cbPublicExp);
            ptr += header.cbPublicExp;
        }
        if (header.cbModulus)
        {
            n.assign(ptr, ptr + header.cbModulus);
            ptr += header.cbModulus;
        }
    }

    // Export private key — must use BCRYPT_RSAFULLPRIVATE_BLOB to get all CRT
    // parameters (dp, dq, iqmp, d). BCRYPT_RSAPRIVATE_BLOB only contains p and q.
    ULONG priv_size = 0;
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_RSAFULLPRIVATE_BLOB,
                             nullptr,
                             0,
                             &priv_size,
                             0);
    vector<unsigned char> priv_blob;
    if (BCRYPT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL)
    {
        priv_blob.resize(priv_size);
        ULONG priv_blob_size = static_cast<ULONG>(priv_blob.size());
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_RSAFULLPRIVATE_BLOB,
                                 priv_blob.data(),
                                 priv_blob_size,
                                 &priv_size,
                                 0);
        if (!BCRYPT_SUCCESS(status))
        {
            // If private export fails, clear private blob but continue
            priv_blob.clear();
        }
        else
        {
            priv_blob.resize(priv_size);
        }
    }

    // Parse private blob for remaining parameters if present
    vector<unsigned char> d, p, q, dp, dq, iqmp;
    if (priv_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
    {
        BCRYPT_RSAKEY_BLOB header{};
        copy_n(priv_blob.data(), sizeof(header), reinterpret_cast<unsigned char *>(&header));

        // Full private blob layout (BCRYPT_RSAFULLPRIVATE_BLOB, Magic =
        // BCRYPT_RSAFULLPRIVATE_MAGIC):
        //   PublicExponent   (cbPublicExp bytes)
        //   Modulus          (cbModulus bytes)
        //   Prime1 / p       (cbPrime1 bytes)
        //   Prime2 / q       (cbPrime2 bytes)
        //   Exponent1 / dp   (cbPrime1 bytes)   -- d mod (p-1)
        //   Exponent2 / dq   (cbPrime2 bytes)   -- d mod (q-1)
        //   Coefficient/iqmp (cbPrime1 bytes)   -- q^-1 mod p
        //   PrivateExp / d   (cbModulus bytes)
        // See:
        // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
        size_t const expected_priv_size = sizeof(BCRYPT_RSAKEY_BLOB) + header.cbPublicExp +
                                          2 * header.cbModulus + 3 * header.cbPrime1 +
                                          2 * header.cbPrime2;
        if (priv_blob.size() < expected_priv_size)
        {
            // Blob is malformed; discard private material and continue with public key only
            priv_blob.clear();
        }
        else
        {
            unsigned char const *ptr = priv_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            // skip public exponent and modulus (already read from public blob)
            ptr += header.cbPublicExp;
            ptr += header.cbModulus;
            // prime1 (p)
            if (header.cbPrime1)
            {
                p.assign(ptr, ptr + header.cbPrime1);
                ptr += header.cbPrime1;
            }
            // prime2 (q)
            if (header.cbPrime2)
            {
                q.assign(ptr, ptr + header.cbPrime2);
                ptr += header.cbPrime2;
            }
            // exponent1 (dp = d mod (p-1))
            if (header.cbPrime1)
            {
                dp.assign(ptr, ptr + header.cbPrime1);
                ptr += header.cbPrime1;
            }
            // exponent2 (dq = d mod (q-1))
            if (header.cbPrime2)
            {
                dq.assign(ptr, ptr + header.cbPrime2);
                ptr += header.cbPrime2;
            }
            // coefficient (iqmp = q^-1 mod p, same size as prime1)
            if (header.cbPrime1)
            {
                iqmp.assign(ptr, ptr + header.cbPrime1);
                ptr += header.cbPrime1;
            }
            // private exponent d
            if (header.cbModulus)
            {
                d.assign(ptr, ptr + header.cbModulus);
                ptr += header.cbModulus;
            }
        }
    }

    // If we didn't get n/e from pub_blob, try to get from priv_blob header
    if (n.empty() && !priv_blob.empty() && priv_blob.size() >= sizeof(BCRYPT_RSAKEY_BLOB))
    {
        auto hdr2 = reinterpret_cast<BCRYPT_RSAKEY_BLOB const *>(priv_blob.data());
        unsigned char const *ptr2 = priv_blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        if (hdr2->cbPublicExp)
        {
            e.assign(ptr2, ptr2 + hdr2->cbPublicExp);
            ptr2 += hdr2->cbPublicExp;
        }
        if (hdr2->cbModulus)
        {
            n.assign(ptr2, ptr2 + hdr2->cbModulus);
            ptr2 += hdr2->cbModulus;
        }
    }

    // Transfer ownership of the CNG handles to the key wrapper.
    // The CNGRSAKey destructor will clean them up via the guard members.
    return make_unique<CNGRSAKey>(std::move(n),
                                  std::move(e),
                                  std::move(d),
                                  std::move(p),
                                  std::move(q),
                                  std::move(dp),
                                  std::move(dq),
                                  std::move(iqmp),
                                  pub_blob,
                                  priv_blob,
                                  key_guard.release(),
                                  alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateRSA(vector<unsigned char> const &n_bytes,
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

    // CNG only supports public-only or full-CRT private import; a bare-d key (without
    // the CRT parameters) cannot be imported because CNG needs p, q, dp, dq, qi to operate.
    bool const has_crt = !d_bytes.empty() && !p_bytes.empty() && !q_bytes.empty() &&
                         !dp_bytes.empty() && !dq_bytes.empty() && !qi_bytes.empty();
    if (!d_bytes.empty() && !has_crt)
    {
        throw runtime_error("CNG RSA import requires either a public key (n, e) or a full "
                            "private key with CRT parameters (n, e, d, p, q, dp, dq, qi)");
    }

    // Build the BCRYPT_RSAKEY_BLOB header followed by the key material.
    // Full private blob layout (BCRYPT_RSAFULLPRIVATE_BLOB):
    //   BCRYPT_RSAKEY_BLOB header
    //   PublicExponent  (cbPublicExp bytes)
    //   Modulus         (cbModulus   bytes)
    //   Prime1 / p      (cbPrime1    bytes)
    //   Prime2 / q      (cbPrime2    bytes)
    //   Exponent1 / dp  (cbPrime1    bytes)  -- d mod (p-1)
    //   Exponent2 / dq  (cbPrime2    bytes)  -- d mod (q-1)
    //   Coefficient/qi  (cbPrime1    bytes)  -- q^-1 mod p
    //   PrivateExp / d  (cbModulus   bytes)
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = has_crt ? BCRYPT_RSAFULLPRIVATE_MAGIC : BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = static_cast<ULONG>(n_bytes.size() * 8);
    header.cbPublicExp = static_cast<ULONG>(e_bytes.size());
    header.cbModulus = static_cast<ULONG>(n_bytes.size());
    header.cbPrime1 = has_crt ? static_cast<ULONG>(p_bytes.size()) : 0;
    header.cbPrime2 = has_crt ? static_cast<ULONG>(q_bytes.size()) : 0;

    vector<unsigned char> blob(sizeof(BCRYPT_RSAKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), e_bytes.begin(), e_bytes.end());
    blob.insert(blob.end(), n_bytes.begin(), n_bytes.end());
    if (has_crt)
    {
        blob.insert(blob.end(), p_bytes.begin(), p_bytes.end());
        blob.insert(blob.end(), q_bytes.begin(), q_bytes.end());
        blob.insert(blob.end(), dp_bytes.begin(), dp_bytes.end());
        blob.insert(blob.end(), dq_bytes.begin(), dq_bytes.end());
        blob.insert(blob.end(), qi_bytes.begin(), qi_bytes.end());
        blob.insert(blob.end(), d_bytes.begin(), d_bytes.end());
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    LPCWSTR const blob_type = has_crt ? BCRYPT_RSAFULLPRIVATE_BLOB : BCRYPT_RSAPUBLIC_BLOB;
    status = BCryptImportKeyPair(alg_guard.get(),
                                 nullptr,
                                 blob_type,
                                 &hKey,
                                 blob.data(),
                                 static_cast<ULONG>(blob.size()),
                                 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    return make_unique<CNGRSAKey>(n_bytes,
                                  e_bytes,
                                  d_bytes,
                                  p_bytes,
                                  q_bytes,
                                  dp_bytes,
                                  dq_bytes,
                                  qi_bytes,
                                  vector<unsigned char>{},
                                  vector<unsigned char>{},
                                  key_guard.release(),
                                  alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateEC(string const &curve) const
{
    LPCWSTR alg = nullptr;
    string curve_name;
    if (curve == "P-256" || curve == "prime256v1")
    {
        alg = BCRYPT_ECDH_P256_ALGORITHM;
        curve_name = "P-256";
    }
    else if (curve == "P-384" || curve == "secp384r1")
    {
        alg = BCRYPT_ECDH_P384_ALGORITHM;
        curve_name = "P-384";
    }
    else if (curve == "P-521" || curve == "secp521r1")
    {
        alg = BCRYPT_ECDH_P521_ALGORITHM;
        curve_name = "P-521";
    }
    else
    {
        throw runtime_error("Unsupported curve: " + curve);
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateKeyPair(alg_guard.get(), &hKey, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenerateKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    status = BCryptFinalizeKeyPair(key_guard.get(), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinalizeKeyPair failed: " + getErrorString());
    }

    // Export public key
    ULONG pub_size = 0;
    status =
        BCryptExportKey(key_guard.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &pub_size, 0);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL)
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    vector<unsigned char> pub_blob(pub_size);
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_ECCPUBLIC_BLOB,
                             pub_blob.data(),
                             static_cast<ULONG>(pub_blob.size()),
                             &pub_size,
                             0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptExportKey (public) failed: " + getErrorString());
    }

    // Parse x and y from the public blob.
    // BCRYPT_ECCKEY_BLOB layout (BCRYPT_ECCPUBLIC_BLOB):
    //   Magic  (ULONG)           -- e.g. BCRYPT_ECDH_PUBLIC_P256_MAGIC
    //   cbKey  (ULONG)           -- byte length of each coordinate
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    vector<unsigned char> x, y;
    if (pub_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB))
    {
        BCRYPT_ECCKEY_BLOB ecc_header{};
        copy_n(pub_blob.data(), sizeof(ecc_header), reinterpret_cast<unsigned char *>(&ecc_header));

        size_t const expected_ecc_pub_size = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ecc_header.cbKey;
        if (pub_blob.size() < expected_ecc_pub_size)
        {
            throw runtime_error("BCryptExportKey returned a truncated ECC public blob");
        }

        unsigned char const *ptr = pub_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        x.assign(ptr, ptr + ecc_header.cbKey);
        ptr += ecc_header.cbKey;
        y.assign(ptr, ptr + ecc_header.cbKey);
    }

    // Export private key
    ULONG priv_size = 0;
    status = BCryptExportKey(key_guard.get(),
                             nullptr,
                             BCRYPT_ECCPRIVATE_BLOB,
                             nullptr,
                             0,
                             &priv_size,
                             0);
    vector<unsigned char> priv_blob;
    if (BCRYPT_SUCCESS(status) || status == STATUS_BUFFER_TOO_SMALL)
    {
        priv_blob.resize(priv_size);
        status = BCryptExportKey(key_guard.get(),
                                 nullptr,
                                 BCRYPT_ECCPRIVATE_BLOB,
                                 priv_blob.data(),
                                 static_cast<ULONG>(priv_blob.size()),
                                 &priv_size,
                                 0);
        if (!BCRYPT_SUCCESS(status))
        {
            priv_blob.clear();
        }
        else
        {
            priv_blob.resize(priv_size);
        }
    }

    // Parse d from the private blob.
    // BCRYPT_ECCKEY_BLOB layout (BCRYPT_ECCPRIVATE_BLOB):
    //   Magic  (ULONG)
    //   cbKey  (ULONG)    -- byte length of each coordinate / scalar
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    //   d      (cbKey bytes)  -- private key scalar
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    vector<unsigned char> d;
    if (priv_blob.size() >= sizeof(BCRYPT_ECCKEY_BLOB))
    {
        BCRYPT_ECCKEY_BLOB ecc_priv_header{};
        copy_n(priv_blob.data(),
               sizeof(ecc_priv_header),
               reinterpret_cast<unsigned char *>(&ecc_priv_header));

        size_t const expected_ecc_priv_size =
            sizeof(BCRYPT_ECCKEY_BLOB) + 3 * ecc_priv_header.cbKey;
        if (priv_blob.size() < expected_ecc_priv_size)
        {
            priv_blob.clear();
        }
        else
        {
            // skip X and Y (already have them from public blob)
            unsigned char const *ptr =
                priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * ecc_priv_header.cbKey;
            d.assign(ptr, ptr + ecc_priv_header.cbKey);
        }
    }

    // Transfer ownership of the CNG handles to the key wrapper.
    return make_unique<CNGECKey>(curve_name,
                                 x,
                                 y,
                                 d,
                                 std::move(pub_blob),
                                 std::move(priv_blob),
                                 key_guard.release(),
                                 alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateEC(string const &curve,
                                       vector<unsigned char> const &x_bytes,
                                       vector<unsigned char> const &y_bytes,
                                       vector<unsigned char> const &d_bytes) const
{
    if (x_bytes.empty() || y_bytes.empty())
    {
        throw runtime_error("EC import requires both x and y coordinates");
    }

    // Resolve the curve to its CNG algorithm identifier and the two magic values
    // (public and private) used in BCRYPT_ECCKEY_BLOB.
    // BCRYPT_ECCKEY_BLOB layout:
    //   Magic  (ULONG)  -- identifies curve + public/private
    //   cbKey  (ULONG)  -- byte length of each coordinate / scalar
    //   X      (cbKey bytes)
    //   Y      (cbKey bytes)
    //   [d     (cbKey bytes)]  -- only present in BCRYPT_ECCPRIVATE_BLOB
    // See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    LPCWSTR alg_id = nullptr;
    ULONG pub_magic = 0;
    ULONG priv_magic = 0;
    string curve_name;

    if (curve == "P-256" || curve == "prime256v1")
    {
        alg_id = BCRYPT_ECDH_P256_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P256_MAGIC;
        curve_name = "P-256";
    }
    else if (curve == "P-384" || curve == "secp384r1")
    {
        alg_id = BCRYPT_ECDH_P384_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P384_MAGIC;
        curve_name = "P-384";
    }
    else if (curve == "P-521" || curve == "secp521r1")
    {
        alg_id = BCRYPT_ECDH_P521_ALGORITHM;
        pub_magic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
        priv_magic = BCRYPT_ECDH_PRIVATE_P521_MAGIC;
        curve_name = "P-521";
    }
    else
    {
        throw runtime_error("Unsupported EC curve: " + curve);
    }

    bool const has_private = !d_bytes.empty();

    // Build the import blob
    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = has_private ? priv_magic : pub_magic;
    header.cbKey = static_cast<ULONG>(x_bytes.size());

    vector<unsigned char> blob(sizeof(BCRYPT_ECCKEY_BLOB));
    copy_n(reinterpret_cast<unsigned char const *>(&header), sizeof(header), blob.data());
    blob.insert(blob.end(), x_bytes.begin(), x_bytes.end());
    blob.insert(blob.end(), y_bytes.begin(), y_bytes.end());
    if (has_private)
    {
        blob.insert(blob.end(), d_bytes.begin(), d_bytes.end());
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, alg_id, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(hAlg);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    LPCWSTR const blob_type = has_private ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB;
    status = BCryptImportKeyPair(alg_guard.get(),
                                 nullptr,
                                 blob_type,
                                 &hKey,
                                 blob.data(),
                                 static_cast<ULONG>(blob.size()),
                                 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptImportKeyPair failed: " + getErrorString());
    }
    KeyHandle key_guard(hKey);

    // Reconstruct the raw blobs in the same format that generateEC(curve) produces
    // so that getPublicBlob() / getPrivateBlob() remain consistent.
    ULONG const cb_key = static_cast<ULONG>(x_bytes.size());

    vector<unsigned char> pub_blob(sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb_key);
    BCRYPT_ECCKEY_BLOB pub_hdr{};
    pub_hdr.dwMagic = pub_magic;
    pub_hdr.cbKey = cb_key;
    copy_n(reinterpret_cast<unsigned char const *>(&pub_hdr), sizeof(pub_hdr), pub_blob.data());
    unsigned char *pub_ptr = pub_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
    copy(x_bytes.begin(), x_bytes.end(), pub_ptr);
    copy(y_bytes.begin(), y_bytes.end(), pub_ptr + cb_key);

    vector<unsigned char> priv_blob;
    if (has_private)
    {
        priv_blob.resize(sizeof(BCRYPT_ECCKEY_BLOB) + 3 * cb_key);
        BCRYPT_ECCKEY_BLOB priv_hdr{};
        priv_hdr.dwMagic = priv_magic;
        priv_hdr.cbKey = cb_key;
        copy_n(reinterpret_cast<unsigned char const *>(&priv_hdr),
               sizeof(priv_hdr),
               priv_blob.data());
        unsigned char *priv_ptr = priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
        copy(x_bytes.begin(), x_bytes.end(), priv_ptr);
        copy(y_bytes.begin(), y_bytes.end(), priv_ptr + cb_key);
        copy(d_bytes.begin(), d_bytes.end(), priv_ptr + 2 * cb_key);
    }

    return make_unique<CNGECKey>(curve_name,
                                 x_bytes,
                                 y_bytes,
                                 d_bytes,
                                 std::move(pub_blob),
                                 std::move(priv_blob),
                                 key_guard.release(),
                                 alg_guard.release());
}

unique_ptr<Key> CNGBackEnd::generateOct(unsigned int bits) const
{
    if (bits == 0 || bits % 8 != 0)
    {
        throw runtime_error("Key size must be a non-zero multiple of 8 bits");
    }

    vector<unsigned char> key_bytes(bits / 8);

    NTSTATUS const status = BCryptGenRandom(nullptr,
                                            key_bytes.data(),
                                            static_cast<ULONG>(key_bytes.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGenRandom failed: " + getErrorString());
    }

    return make_unique<OctKey>(std::move(key_bytes));
}

unique_ptr<Key> CNGBackEnd::generateOct(unsigned int bits,
                                        vector<unsigned char> const &k_bytes) const
{
    auto const key_size(k_bytes.size());
    if (key_size != bits / 8)
    {
        throw runtime_error("Key size error");
    }

    return make_unique<OctKey>(std::move(k_bytes));
}

unique_ptr<Key> CNGBackEnd::generateOkp(Use use, unsigned int bits) const
{
    throw runtime_error("Not supported on Windows/CNG. Use an OpenSSL version.");
}

unique_ptr<Key> CNGBackEnd::generateOkp(string const &curve,
                                        vector<unsigned char> const &x_bytes,
                                        vector<unsigned char> const &d_bytes) const
{
    (void)curve;
    (void)x_bytes;
    (void)d_bytes;
    throw runtime_error("Not supported on Windows/CNG. Use an OpenSSL version.");
}

// vector<unsigned char> CNGBackEnd::sign(SignatureAlgorithm algorithm, JWK const& key,
//                                         vector<unsigned char> const& data) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }
//
// bool CNGBackEnd::verify(SignatureAlgorithm algorithm, JWK const& key,
//                     vector<unsigned char> const& data,
//                     vector<unsigned char> const& signature) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }
//
//
// vector<unsigned char> CNGBackEnd::encrypt(ContentEncryptionAlgorithm algorithm, JWK const& key,
//         vector<unsigned char> const& plaintext) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }
//
//
// vector<unsigned char> CNGBackEnd::decrypt(ContentEncryptionAlgorithm algorithm, JWK const& key,
//         vector<unsigned char> const& ciphertext) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }

vector<unsigned char> CNGBackEnd::hash(HashAlgorithm algorithm,
                                       vector<unsigned char> const &data) const
{
    wchar_t const *algorithm_name(nullptr);
    switch (algorithm)
    {
        case HashAlgorithm::sha256:
            algorithm_name = BCRYPT_SHA256_ALGORITHM;
            break;
        case HashAlgorithm::sha384:
            algorithm_name = BCRYPT_SHA384_ALGORITHM;
            break;
        case HashAlgorithm::sha512:
            algorithm_name = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            throw runtime_error("Unsupported hash algorithm");
    }

    BCRYPT_ALG_HANDLE h_alg(nullptr);
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, algorithm_name, nullptr, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptOpenAlgorithmProvider failed: " + getErrorString());
    }
    AlgHandle alg_guard(h_alg);

    ULONG hash_object_length(0);
    ULONG result_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_object_length),
                               sizeof(hash_object_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + getErrorString());
    }

    ULONG hash_length(0);
    status = BCryptGetProperty(alg_guard.get(),
                               BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hash_length),
                               sizeof(hash_length),
                               &result_length,
                               0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed: " + getErrorString());
    }

    vector<unsigned char> hash_object(hash_object_length);
    BCRYPT_HASH_HANDLE h_hash(nullptr);
    status = BCryptCreateHash(alg_guard.get(),
                              &h_hash,
                              hash_object.empty() ? nullptr : hash_object.data(),
                              static_cast<ULONG>(hash_object.size()),
                              nullptr,
                              0,
                              0);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptCreateHash failed: " + getErrorString());
    }

    if (!data.empty())
    {
        status = BCryptHashData(h_hash,
                                const_cast<PUCHAR>(data.data()),
                                static_cast<ULONG>(data.size()),
                                0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptDestroyHash(h_hash);
            throw runtime_error("BCryptHashData failed: " + getErrorString());
        }
    }

    vector<unsigned char> digest(hash_length);
    status = BCryptFinishHash(h_hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(h_hash);
    if (!BCRYPT_SUCCESS(status))
    {
        throw runtime_error("BCryptFinishHash failed: " + getErrorString());
    }

    return digest;
}
//
// vector<unsigned char> CNGBackEnd::derive(JWK const& private_key,
//                                          JWK const& peer_key) const
//{
//    throw logic_error("Not yet implemented");
//    return {};
//}
//
// vector<unsigned char> CNGBackEnd::randomBytes(size_t size) const
//{
//    throw logic_error("Not yet implemented");
//    return {};
//}

/// Base64 encode
string CNGBackEnd::base64Encode(vector<unsigned char> const &data) const
{
    if (data.empty())
    {
        return string();
    }

    // Use Windows CryptoAPI to perform base64 encoding
    DWORD required = 0;
    if (!CryptBinaryToStringA(data.data(),
                              static_cast<DWORD>(data.size()),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              nullptr,
                              &required))
    {
        throw runtime_error("CryptBinaryToStringA failed: " + getErrorString());
    }

    string output;
    output.resize(required);

    if (!CryptBinaryToStringA(data.data(),
                              static_cast<DWORD>(data.size()),
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              &output[0],
                              &required))
    {
        throw runtime_error("CryptBinaryToStringA failed: " + getErrorString());
    }

    // CryptBinaryToStringA writes a null-terminated string; remove the terminator
    if (!output.empty() && output.back() == '\0')
    {
        output.pop_back();
    }

    return output;
}
/// Base64 decode
vector<unsigned char> CNGBackEnd::base64Decode(string const &encoded) const
{
    if (encoded.empty())
    {
        return {};
    }

    // Remove CR/LF from the input so decoding accepts inputs with newlines
    string cleaned;
    cleaned.reserve(encoded.size());
    for (unsigned char c : encoded)
    {
        if (c == '\r' || c == '\n')
            continue;
        cleaned.push_back(static_cast<char>(c));
    }

    if (cleaned.empty())
    {
        return {};
    }

    DWORD required = 0;
    // Determine required buffer size
    if (!CryptStringToBinaryA(cleaned.c_str(),
                              static_cast<DWORD>(cleaned.size()),
                              CRYPT_STRING_BASE64,
                              nullptr,
                              &required,
                              nullptr,
                              nullptr))
    {
        throw runtime_error("CryptStringToBinaryA failed: " + getErrorString());
    }

    vector<unsigned char> output;
    output.resize(required);

    if (!CryptStringToBinaryA(cleaned.c_str(),
                              static_cast<DWORD>(cleaned.size()),
                              CRYPT_STRING_BASE64,
                              output.data(),
                              &required,
                              nullptr,
                              nullptr))
    {
        throw runtime_error("CryptStringToBinaryA failed: " + getErrorString());
    }

    // If required was adjusted to a smaller value, resize to actual
    output.resize(required);

    return output;
}

string CNGBackEnd::getErrorString() const
{
    DWORD err = ::GetLastError();
    if (err == 0)
    {
        return string();
    }

    LPSTR msg_buf = nullptr;
    DWORD size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                    FORMAT_MESSAGE_IGNORE_INSERTS,
                                nullptr,
                                err,
                                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                reinterpret_cast<LPSTR>(&msg_buf),
                                0,
                                nullptr);

    string msg;
    if (size && msg_buf)
    {
        msg.assign(msg_buf, size);
        LocalFree(msg_buf);
    }
    else
    {
        msg = string("Unknown error ") + to_string(err);
    }

    return msg;
}

///// Get hash algorithm for signature
// void const*
// CNGBackEnd::getHashAlgorithm(SignatureAlgorithm signature_algorithm) const
//{
//     throw logic_error("Not yet implemented");
//     return {};
// }

}  // namespace Private

}  // namespace JOSE
}  // namespace Vlinder
