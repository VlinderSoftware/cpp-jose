#pragma once

#include "back_end.hpp"

#include <memory>

namespace Vlinder {
namespace JOSE {
namespace Private {

class BackEndFactory
{
public:
    virtual ~BackEndFactory() = default;
    virtual std::unique_ptr<BackEnd> createBackEnd() const = 0;

    static BackEndFactory& get();
};

} // namespace Private
} // namespace JOSE
} // namespace Vlinder
