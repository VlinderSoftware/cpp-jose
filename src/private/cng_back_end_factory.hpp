#include "back_end_factory.hpp"
#include "cng_back_end.hpp"

namespace Vlinder {
namespace JOSE {
namespace Private {

class CNGBackEndFactory : public BackEndFactory
{
public:
    std::unique_ptr<BackEnd> createBackEnd() const override
    {
        return std::make_unique<CNGBackEnd>();
    }
};

}  // namespace Private
}  // namespace JOSE
}  // namespace Vlinder
