#ifndef JOSE_JOSE_HPP
#define JOSE_JOSE_HPP

/**
 * @file jose.hpp
 * @brief Main header file for cpp-jose library
 *
 * A complete modern C++ implementation of the JOSE RFCs:
 * - RFC 7515: JSON Web Signature (JWS)
 * - RFC 7516: JSON Web Encryption (JWE)
 * - RFC 7517: JSON Web Key (JWK)
 * - RFC 7518: JSON Web Algorithms (JWA)
 * - RFC 7519: JSON Web Token (JWT)
 * - RFC 7520: Examples of JOSE
 * - RFC 7638: JSON Web Key (JWK) Thumbprint
 *
 * Using OpenSSL for cryptographic operations with support for
 * OKP keys such as Ed25519/Ed448 and X25519/X448.
 */

#include "base64url.hpp"
#include "jwa.hpp"
#include "jwe.hpp"
#include "jwk.hpp"
#include "jwk_set.hpp"
#include "jwk_thumbprint.hpp"
#include "jws.hpp"
#include "jwt.hpp"

#endif  // JOSE_JOSE_HPP
