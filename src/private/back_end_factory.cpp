#include "back_end_factory.hpp"
#if defined(JOSE_USE_OPENSSL)
#include "openssl_back_end_factory.hpp"
#elif defined(JOSE_USE_CNG)
#include "cng_back_end_factory.hpp"
#else
#error "No crypto back-end defined. Please define USE_OPENSSL or USE_CNG."
#endif

#include <mutex>

using namespace std;

namespace Vlinder {
namespace JOSE {
namespace Private {

BackEndFactory &BackEndFactory::get()
{
#if defined(JOSE_USE_OPENSSL)
    static OpenSSLBackEndFactory factory;
    return factory;
#elif defined(JOSE_USE_CNG)
    static CNGBackEndFactory factory;
    return factory;
#else
#error "No crypto backend defined. Please define USE_OPENSSL or USE_CNG."
#endif
}

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
