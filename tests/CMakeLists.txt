cmake_minimum_required(VERSION 3.14)

# GoogleTest setup
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()

# Test executable
add_executable(jose_tests
    test_base64url.cpp
    # test_json.cpp - Removed because JsonValue class was replaced with nlohmann::json
    test_jwk.cpp
    test_jwa.cpp
    test_jws.cpp
    test_jwe.cpp
    test_jwt.cpp
    test_jwk_thumbprint.cpp
    test_rfc7520_examples.cpp
)

target_link_libraries(jose_tests
    jose
    nlohmann_json::nlohmann_json
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(jose_tests)

# Coverage flags
if(CMAKE_BUILD_TYPE MATCHES Debug)
    if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(jose_tests PRIVATE --coverage)
        target_link_options(jose_tests PRIVATE --coverage)
    endif()
endif()
