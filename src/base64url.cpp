#include <mutex>
#include "base64url.hpp"
#include "private/back_end_factory.hpp"

#include <cstring>
#include <stdexcept>

using namespace std;

namespace Vlinder {
namespace JOSE {
namespace {


Private::BackEnd &getBackEnd()
{
    static once_flag flag;
    static unique_ptr<Private::BackEnd> back_end;
    call_once(flag,
              [&]()
              {
                  back_end = move(Private::BackEndFactory::get().createBackEnd());
              });
    return *back_end;
}
}

std::string Base64Url::encode(std::vector<unsigned char> const &data)
{
    if (data.empty())
    {
        return "";
    }

    auto const &back_end = getBackEnd();
    std::string result = back_end.base64Encode(data);

    for (char &c : result)
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

std::string Base64Url::encode(std::string const &str)
{
    std::vector<unsigned char> const data(str.begin(), str.end());
    return encode(data);
}

std::vector<unsigned char> Base64Url::decode(std::string const &encoded)
{
    if (encoded.empty())
    {
        return {};
    }
    std::string base64 = encoded;
    for (char &c : base64)
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
    while (base64.length() % 4 != 0)
    {
        base64 += '=';
    }
    auto const &back_end = getBackEnd();
    return back_end.base64Decode(base64);
}

std::string Base64Url::decodeToString(std::string const &encoded)
{
    auto const data = decode(encoded);
    return std::string(data.begin(), data.end());
}

}  // namespace JOSE
}  // namespace Vlinder
