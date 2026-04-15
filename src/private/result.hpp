#pragma once

#include <optional>
#include <string>
#include <utility>

namespace Vlinder::JOSE::Private {

/// @brief Lightweight result type used internally by the JOSE library.
///
/// `Result< T >` carries either a successful value of type `T` or a
/// human-readable error message. It is **not** part of the public API —
/// callers see either a throwing overload or a `std::optional< T >` nothrow
/// overload.
///
/// Use the helpers `makeOk` and `makeError` to construct values, and
/// structured bindings with early return to propagate errors:
///
/// @code
/// auto [val_opt, val_err] = someCall();
/// if (!val_opt) return makeError< TargetType >(std::move(val_err));
/// auto val = std::move(*val_opt);
/// @endcode
///
/// RFC reference: internal idiom; no RFC mandate.
template <typename T>
using Result = std::pair<std::optional<T>, std::string>;

/// @brief Construct a successful Result containing @p value.
/// @param value  The success value to wrap.
/// @return Result< T > with a populated optional and an empty error string.
template <typename T>
Result<T> makeOk(T value)
{
    return {std::optional<T>{std::move(value)}, std::string{}};
}

/// @brief Construct an error Result with no value.
/// @param msg  Human-readable description of the failure.
/// @return Result< T > with an empty optional and the supplied error string.
template <typename T>
Result<T> makeError(std::string msg)
{
    return {std::optional<T>{std::nullopt}, std::move(msg)};
}

}  // namespace Vlinder::JOSE::Private
