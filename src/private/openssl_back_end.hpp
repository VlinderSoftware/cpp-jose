#pragma once

#include "back_end.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

class OpenSSLRSAKey : public RSAKey
{
public:
    OpenSSLRSAKey(std::vector<unsigned char> const &n,
                  std::vector<unsigned char> const &e,
                  std::vector<unsigned char> const &d,
                  std::vector<unsigned char> const &p,
                  std::vector<unsigned char> const &q,
                  std::vector<unsigned char> const &dp,
                  std::vector<unsigned char> const &dq,
                  std::vector<unsigned char> const &qi,
                  std::vector<unsigned char> const &public_blob,
                  std::vector<unsigned char> const &private_blob);

    std::vector<unsigned char> getPublicBlob() const override;
    std::vector<unsigned char> getPrivateBlob() const override;
    bool hasPrivate() const override;
    std::unique_ptr<Key> clone() const override;

    std::vector<unsigned char> getN() const override;
    std::vector<unsigned char> getE() const override;
    std::vector<unsigned char> getD() const override;
    std::vector<unsigned char> getP() const override;
    std::vector<unsigned char> getQ() const override;
    std::vector<unsigned char> getDp() const override;
    std::vector<unsigned char> getDq() const override;
    std::vector<unsigned char> getQi() const override;

private:
    std::vector<unsigned char> n_;
    std::vector<unsigned char> e_;
    std::vector<unsigned char> d_;
    std::vector<unsigned char> p_;
    std::vector<unsigned char> q_;
    std::vector<unsigned char> dp_;
    std::vector<unsigned char> dq_;
    std::vector<unsigned char> qi_;
    std::vector<unsigned char> public_blob_;
    std::vector<unsigned char> private_blob_;
};

class OpenSSLECKey : public ECKey
{
public:
    OpenSSLECKey(std::string const &curve_name,
                 std::vector<unsigned char> const &x,
                 std::vector<unsigned char> const &y,
                 std::vector<unsigned char> const &d,
                 std::vector<unsigned char> const &public_blob,
                 std::vector<unsigned char> const &private_blob);

    std::vector<unsigned char> getPublicBlob() const override;
    std::vector<unsigned char> getPrivateBlob() const override;
    bool hasPrivate() const override;
    std::unique_ptr<Key> clone() const override;
    std::vector<unsigned char> getX() const override;
    std::vector<unsigned char> getY() const override;
    std::vector<unsigned char> getD() const override;

private:
    std::vector<unsigned char> x_;
    std::vector<unsigned char> y_;
    std::vector<unsigned char> d_;
    std::vector<unsigned char> public_blob_;
    std::vector<unsigned char> private_blob_;
};

class OpenSSLOKPKey : public OKPKey
{
public:
    OpenSSLOKPKey(std::string const &curve_name,
                  std::vector<unsigned char> const &x,
                  std::vector<unsigned char> const &d,
                  std::vector<unsigned char> const &public_blob,
                  std::vector<unsigned char> const &private_blob);

    std::vector<unsigned char> getPublicBlob() const override;
    std::vector<unsigned char> getPrivateBlob() const override;
    bool hasPrivate() const override;
    std::unique_ptr<Key> clone() const override;
    std::vector<unsigned char> getX() const override;
    std::vector<unsigned char> getD() const override;

private:
    std::vector<unsigned char> x_;
    std::vector<unsigned char> d_;
    std::vector<unsigned char> public_blob_;
    std::vector<unsigned char> private_blob_;
};

class OpenSSLBackEnd : public BackEnd
{
public:
    std::unique_ptr<Key> generateRSA(unsigned int bits) const override;
    std::unique_ptr<Key> generateRSA(std::vector<unsigned char> const &n_bytes,
                                     std::vector<unsigned char> const &e_bytes,
                                     std::vector<unsigned char> const &d_bytes,
                                     std::vector<unsigned char> const &p_bytes,
                                     std::vector<unsigned char> const &q_bytes,
                                     std::vector<unsigned char> const &dp_bytes,
                                     std::vector<unsigned char> const &dq_bytes,
                                     std::vector<unsigned char> const &qi_bytes) const override;

    std::unique_ptr<Key> generateEC(std::string const &curve) const override;
    std::unique_ptr<Key> generateEC(std::string const &curve,
                                    std::vector<unsigned char> const &x_bytes,
                                    std::vector<unsigned char> const &y_bytes,
                                    std::vector<unsigned char> const &d_bytes) const override;

    std::unique_ptr<Key> generateOct(unsigned int bits) const override;
    std::unique_ptr<Key> generateOct(unsigned int bits,
                                     std::vector<unsigned char> const &k_bytes) const override;
    std::unique_ptr<Key> generateOkp(Use use, unsigned int bits) const override;
    std::unique_ptr<Key> generateOkp(std::string const &curve,
                                     std::vector<unsigned char> const &x_bytes,
                                     std::vector<unsigned char> const &d_bytes) const override;

    std::vector<unsigned char> hash(HashAlgorithm algorithm,
                                    std::vector<unsigned char> const &data) const override;

    std::string base64Encode(std::vector<unsigned char> const &data) const override;
    std::vector<unsigned char> base64Decode(std::string const &encoded) const override;
    std::string getErrorString() const override;
};

} // namespace Private
} // namespace JOSE
} // namespace Vlinder
