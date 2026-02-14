#ifndef JOSE_JSON_UTILS_HPP
#define JOSE_JSON_UTILS_HPP

#include <nlohmann/json.hpp>

namespace Vlinder {
namespace JOSE {

// Use nlohmann::json as JsonValue
using json = nlohmann::json;

}  // namespace JOSE
}  // namespace Vlinder

#endif  // JOSE_JSON_UTILS_HPP
