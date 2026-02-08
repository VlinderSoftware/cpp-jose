#include "jose/base64url.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <cstring>
#include <stdexcept>

namespace Vlinder {
namespace jose {

std::string Base64Url::encode(const std::vector<unsigned char>& data)
{
    if (data.empty())
    {
        return "";
    }

    // Use OpenSSL to do base64 encoding
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    // Convert base64 to base64url
    for (char& c : result)
    {
        if (c == '+')
        {
            c = '-';
        }
        else if (c == '/')
        {
            c = '_';
        }
    }

    // Remove padding
    while (!result.empty() && result.back() == '=')
    {
        result.pop_back();
    }

    return result;
}

std::string Base64Url::encode(const std::string& str)
{
    std::vector<unsigned char> data(str.begin(), str.end());
    return encode(data);
}

std::vector<unsigned char> Base64Url::decode(const std::string& encoded)
{
    if (encoded.empty())
    {
        return {};
    }

    // Convert base64url to base64
    std::string base64 = encoded;
    for (char& c : base64)
    {
        if (c == '-')
        {
            c = '+';
        }
        else if (c == '_')
        {
            c = '/';
        }
    }

    // Add padding
    while (base64.length() % 4 != 0)
    {
        base64 += '=';
    }

    // Decode using OpenSSL
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> result(base64.length());
    int decodedLength = BIO_read(bio, result.data(), static_cast<int>(result.size()));

    BIO_free_all(bio);

    if (decodedLength < 0)
    {
        throw std::runtime_error("Failed to decode base64url");
    }

    result.resize(decodedLength);
    return result;
}

std::string Base64Url::decodeToString(const std::string& encoded)
{
    auto data = decode(encoded);
    return std::string(data.begin(), data.end());
}

}  // namespace jose
}  // namespace Vlinder
