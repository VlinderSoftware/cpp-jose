// generateRSA
// EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
// if (!ctx)
//{
//    throw runtime_error("Failed to create EVP_PKEY_CTX");
//}

// if (EVP_PKEY_keygen_init(ctx) <= 0)
//{
//     EVP_PKEY_CTX_free(ctx);
//     throw runtime_error("Failed to initialize key generation");
// }

// if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
//{
//     EVP_PKEY_CTX_free(ctx);
//     throw runtime_error("Failed to set key size");
// }

// if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey_) <= 0)
//{
//     EVP_PKEY_CTX_free(ctx);
//     throw runtime_error("Failed to generate key");
// }

// EVP_PKEY_CTX_free(ctx);
//
//// Automatically set key ID to SHA-512 thumbprint of the public key
// jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");
//
//// Determine algorithm: use provided or default
// string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::rsa, use) : alg;
//
//// Validate algorithm matches key type and use
// validateAlgorithm(final_alg, KeyType::rsa, use);
//
//// Set metadata
// jwk.impl_->alg_ = final_alg;
// jwk.impl_->use_ = use;
// jwk.impl_->has_use_ = true;


#if 0
generate EC
    JWK jwk;
    jwk.impl_->key_type_ = KeyType::ec;

    int nid;
    if (curve == "P-256")
    {
        nid = NID_X9_62_prime256v1;
    }
    else if (curve == "P-384")
    {
        nid = NID_secp384r1;
    }
    else if (curve == "P-521")
    {
        nid = NID_secp521r1;
    }
    else
    {
        throw runtime_error("Unsupported curve");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx)
    {
        throw runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to initialize key generation");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to set curve");
    }

    if (EVP_PKEY_keygen(ctx, &jwk.impl_->pkey_) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to generate key");
    }

    EVP_PKEY_CTX_free(ctx);
    
    // Automatically set key ID to SHA-512 thumbprint of the public key
    jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");
    
    // Determine algorithm: use provided or default based on curve
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::ec, use, curve) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::ec, use);
    
    // Set metadata
    jwk.impl_->alg_ = final_alg;
    jwk.impl_->use_ = use;
    jwk.impl_->has_use_ = true;
    
    return jwk;
#endif

    #if 0
        JWK jwk;
    jwk.impl_->key_type_ = KeyType::oct;

    vector<unsigned char> key(bits / 8);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1)
    {
        throw runtime_error("Failed to generate random key");
    }

    jwk.impl_->pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, key.data(), key.size());
    if (!jwk.impl_->pkey_)
    {
        throw runtime_error("Failed to create symmetric key");
    }

    // Automatically set key ID to SHA-512 thumbprint
    jwk.impl_->kid_ = JWKThumbprint::compute(jwk, "SHA-512");

    // Determine algorithm: use provided or default
    string final_alg = alg.empty() ? getDefaultAlgorithm(KeyType::oct, use) : alg;
    
    // Validate algorithm matches key type and use
    validateAlgorithm(final_alg, KeyType::oct, use);
    
    // Set metadata
    jwk.impl_->alg_ = final_alg;
    jwk.impl_->use_ = use;
    jwk.impl_->has_use_ = true;

    return jwk;
#endif


#if 0
#if 0

        // Use EVP_PKEY_get_bn_param for OpenSSL 3.0+
        BIGNUM* n = nullptr;
        BIGNUM* e = nullptr;
        BIGNUM* d = nullptr;
        
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_N, &n);
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_E, &e);
        
        if (n)
        {
            vector<unsigned char> n_bytes(BN_num_bytes(n));
            BN_bn2bin(n, n_bytes.data());
            json_obj["n"] = Base64Url::encode(n_bytes);
            BN_free(n);
        }

        if (e)
        {
            vector<unsigned char> e_bytes(BN_num_bytes(e));
            BN_bn2bin(e, e_bytes.data());
            json_obj["e"] = Base64Url::encode(e_bytes);
            BN_free(e);
        }

        if (include_private)
        {
            EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_D, &d);
            if (d)
            {
                vector<unsigned char> d_bytes(BN_num_bytes(d));
                BN_bn2bin(d, d_bytes.data());
                json_obj["d"] = Base64Url::encode(d_bytes);
                BN_free(d);

                BIGNUM *p = nullptr, *q = nullptr, *dmp1 = nullptr, *dmq1 = nullptr, *iqmp = nullptr;
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1);
                EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);

                if (p)
                {
                    vector<unsigned char> p_bytes(BN_num_bytes(p));
                    BN_bn2bin(p, p_bytes.data());
                    json_obj["p"] = Base64Url::encode(p_bytes);
                    BN_free(p);
                }

                if (q)
                {
                    vector<unsigned char> q_bytes(BN_num_bytes(q));
                    BN_bn2bin(q, q_bytes.data());
                    json_obj["q"] = Base64Url::encode(q_bytes);
                    BN_free(q);
                }

                if (dmp1)
                {
                    vector<unsigned char> dp(BN_num_bytes(dmp1));
                    BN_bn2bin(dmp1, dp.data());
                    json_obj["dp"] = Base64Url::encode(dp);
                    BN_free(dmp1);
                }

                if (dmq1)
                {
                    vector<unsigned char> dq(BN_num_bytes(dmq1));
                    BN_bn2bin(dmq1, dq.data());
                    json_obj["dq"] = Base64Url::encode(dq);
                    BN_free(dmq1);
                }

                if (iqmp)
                {
                    vector<unsigned char> qi(BN_num_bytes(iqmp));
                    BN_bn2bin(iqmp, qi.data());
                    json_obj["qi"] = Base64Url::encode(qi);
                    BN_free(iqmp);
                }
            }
        }
#endif
#endif

                    #if 0
        // Get the curve name
        char curve_name[80];
        size_t curve_name_len = sizeof(curve_name);
        string group_name;
        size_t key_size = 0;  // Expected byte size for coordinates
        
        if (EVP_PKEY_get_utf8_string_param(impl_->pkey_, OSSL_PKEY_PARAM_GROUP_NAME, 
                                           curve_name, sizeof(curve_name), &curve_name_len))
        {
            group_name = string(curve_name);
            // Convert OpenSSL curve names to JWK curve names
            if (group_name == "prime256v1")
            {
                json_obj["crv"] = "P-256";
                key_size = 32;
            }
            else if (group_name == "secp384r1")
            {
                json_obj["crv"] = "P-384";
                key_size = 48;
            }
            else if (group_name == "secp521r1")
            {
                json_obj["crv"] = "P-521";
                key_size = 66;
            }
            else
            {
                json_obj["crv"] = group_name;  // Use as-is if unknown
            }
        }

        // Get the public key coordinates (x, y)
        BIGNUM* x = nullptr;
        BIGNUM* y = nullptr;
        
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_EC_PUB_X, &x);
        EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
        
        if (x && key_size > 0)
        {
            vector<unsigned char> x_bytes(key_size, 0);
            int x_len = BN_num_bytes(x);
            // Pad with leading zeros if necessary
            BN_bn2bin(x, x_bytes.data() + (key_size - x_len));
            json_obj["x"] = Base64Url::encode(x_bytes);
            BN_free(x);
        }

        if (y && key_size > 0)
        {
            vector<unsigned char> y_bytes(key_size, 0);
            int y_len = BN_num_bytes(y);
            // Pad with leading zeros if necessary
            BN_bn2bin(y, y_bytes.data() + (key_size - y_len));
            json_obj["y"] = Base64Url::encode(y_bytes);
            BN_free(y);
        }

        // Include private key if requested
        if (include_private && key_size > 0)
        {
            BIGNUM* d = nullptr;
            EVP_PKEY_get_bn_param(impl_->pkey_, OSSL_PKEY_PARAM_PRIV_KEY, &d);
            if (d)
            {
                vector<unsigned char> d_bytes(key_size, 0);
                int d_len = BN_num_bytes(d);
                // Pad with leading zeros if necessary
                BN_bn2bin(d, d_bytes.data() + (key_size - d_len));
                json_obj["d"] = Base64Url::encode(d_bytes);
                BN_free(d);
            }
        }
#endif
