#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <string>
#include <vector>

#include "../src/private/result.hpp"

using namespace std;
using namespace Vlinder::JOSE::Private;

// ---------------------------------------------------------------------------
// makeOk
// ---------------------------------------------------------------------------

TEST_CASE("Result_MakeOk_HasValue", "[result]")
{
    auto r = makeOk(42);
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == 42);
    REQUIRE(r.second.empty());
}

TEST_CASE("Result_MakeOk_String", "[result]")
{
    auto r = makeOk(string{"hello"});
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == "hello");
    REQUIRE(r.second.empty());
}

TEST_CASE("Result_MakeOk_Vector", "[result]")
{
    vector<unsigned char> data = {0x01, 0x02, 0x03};
    auto r = makeOk(data);
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == data);
    REQUIRE(r.second.empty());
}

TEST_CASE("Result_MakeOk_UniquePtr", "[result]")
{
    auto ptr = make_unique<int>(99);
    int *raw = ptr.get();
    auto r = makeOk(move(ptr));
    REQUIRE(r.first.has_value());
    REQUIRE(r.first->get() == raw);
    REQUIRE(r.second.empty());
}

TEST_CASE("Result_MakeOk_Bool", "[result]")
{
    auto r_true = makeOk(true);
    REQUIRE(r_true.first.has_value());
    REQUIRE(*r_true.first == true);

    auto r_false = makeOk(false);
    REQUIRE(r_false.first.has_value());
    REQUIRE(*r_false.first == false);
    REQUIRE(r_false.second.empty());
}

// ---------------------------------------------------------------------------
// makeError
// ---------------------------------------------------------------------------

TEST_CASE("Result_MakeError_HasNoValue", "[result]")
{
    auto r = makeError<int>("something went wrong");
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == "something went wrong");
}

TEST_CASE("Result_MakeError_EmptyMessage", "[result]")
{
    auto r = makeError<string>("");
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second.empty());
}

TEST_CASE("Result_MakeError_PreservesFullMessage", "[result]")
{
    string const msg = "Failed to create RSA key: error:0D07207B:asn1 encoding "
                       "routines:ASN1_get_object:header too long";
    auto r = makeError<vector<unsigned char>>(msg);
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == msg);
}

TEST_CASE("Result_MakeError_UniquePtr", "[result]")
{
    auto r = makeError<unique_ptr<int>>("no key");
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == "no key");
}

// ---------------------------------------------------------------------------
// Structured binding propagation — success path
// ---------------------------------------------------------------------------

namespace {

Result<int> multiplyByTwo(int x)
{
    return makeOk(x * 2);
}

Result<string> intToString(int x)
{
    auto [doubled_opt, doubled_err] = multiplyByTwo(x);
    if (!doubled_opt)
        return makeError<string>(move(doubled_err));
    auto doubled = move(*doubled_opt);
    return makeOk(to_string(doubled));
}

}  // namespace

TEST_CASE("Result_Propagation_SuccessExtractsValue", "[result][propagation]")
{
    auto r = intToString(5);
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == "10");
    REQUIRE(r.second.empty());
}

// ---------------------------------------------------------------------------
// Structured binding propagation — error propagation
// ---------------------------------------------------------------------------

namespace {

Result<int> failingStep(int /*x*/)
{
    return makeError<int>("step failed: bad input");
}

Result<string> chainThatFails(int x)
{
    auto [v_opt, v_err] = failingStep(x);
    if (!v_opt)
        return makeError<string>(move(v_err));
    auto v = move(*v_opt);
    // This line must NOT be reached when failingStep returns an error
    return makeOk(to_string(v));
}

}  // namespace

TEST_CASE("Result_Propagation_ErrorForwardsMessage", "[result][propagation]")
{
    auto r = chainThatFails(7);
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == "step failed: bad input");
}

// ---------------------------------------------------------------------------
// Structured binding propagation — chained calls
// ---------------------------------------------------------------------------

namespace {

Result<int> step1(int x)
{
    if (x < 0)
    {
        return makeError<int>("step1: negative input");
    }
    return makeOk(x + 1);
}

Result<int> step2(int x)
{
    if (x > 100)
    {
        return makeError<int>("step2: overflow");
    }
    return makeOk(x * 10);
}

Result<string> chainedSteps(int x)
{
    auto [a_opt, a_err] = step1(x);
    if (!a_opt)
        return makeError<string>(move(a_err));
    auto a = move(*a_opt);

    auto [b_opt, b_err] = step2(a);
    if (!b_opt)
        return makeError<string>(move(b_err));
    auto b = move(*b_opt);

    return makeOk(to_string(b));
}

}  // namespace

TEST_CASE("Result_ChainedSteps_BothSucceed", "[result][propagation]")
{
    auto r = chainedSteps(3);
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == "40");  // (3+1)*10 = 40
}

TEST_CASE("Result_ChainedSteps_FirstFails", "[result][propagation]")
{
    auto r = chainedSteps(-1);
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == "step1: negative input");
}

TEST_CASE("Result_ChainedSteps_SecondFails", "[result][propagation]")
{
    auto r = chainedSteps(101);  // step1 returns 102, step2 fails
    REQUIRE_FALSE(r.first.has_value());
    REQUIRE(r.second == "step2: overflow");
}

// ---------------------------------------------------------------------------
// Structured binding propagation — move-only types
// ---------------------------------------------------------------------------

namespace {

Result<unique_ptr<int>> makePtr(int x)
{
    return makeOk(make_unique<int>(x));
}

Result<int> extractFromPtr(int x)
{
    auto [ptr_opt, ptr_err] = makePtr(x);
    if (!ptr_opt)
        return makeError<int>(move(ptr_err));
    auto ptr = move(*ptr_opt);
    return makeOk(*ptr);
}

}  // namespace

TEST_CASE("Result_Propagation_MoveOnlyType", "[result][propagation]")
{
    auto r = extractFromPtr(55);
    REQUIRE(r.first.has_value());
    REQUIRE(*r.first == 55);
}

// ---------------------------------------------------------------------------
// Result type alias checks
// ---------------------------------------------------------------------------

TEST_CASE("Result_IsAPair", "[result]")
{
    // Verify the alias expands to the expected pair type
    Result<int> r = makeOk(1);
    static_assert(is_same_v<decltype(r), pair<optional<int>, string>>);
    REQUIRE(true);
}
