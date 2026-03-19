#pragma once

#include <vector>

#include "json_utils.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

void appendDERLength(std::vector<unsigned char> &out, size_t length);

void appendDERInteger(std::vector<unsigned char> &out, std::vector<unsigned char> const &value);

std::vector<unsigned char> buildRSAPrivateKeyPKCS1DERFromJSON(json const &json);

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
