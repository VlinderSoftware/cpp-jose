#include "base64url.hpp"

#include <cstring>
#include <mutex>
#include <stdexcept>

#include "private/back_end_factory.hpp"

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
                  back_end = std::move(Private::BackEndFactory::get().createBackEnd());
              });
    return *back_end;
}
}  // namespace

string Base64URL::encode(span<unsigned char const> const &data)
{
    if (data.empty())
    {
        return "";
    }

    auto const &back_end = getBackEnd();
    string result = back_end.base64Encode(data);

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

string Base64URL::encode(vector<unsigned char> const &data)
{
    return encode(span<unsigned char const>(data.data(), data.size()));
}

string Base64URL::encode(string const &str)
{
    vector<unsigned char> const data(str.begin(), str.end());
    return encode(data);
}

vector<unsigned char> Base64URL::decode(string const &encoded)
{
    if (encoded.empty())
    {
        return {};
    }
    string base64 = encoded;
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

string Base64URL::decodeToString(string const &encoded)
{
    auto const data = decode(encoded);
    return string(data.begin(), data.end());
}

}  // namespace JOSE
}  // namespace Vlinder
