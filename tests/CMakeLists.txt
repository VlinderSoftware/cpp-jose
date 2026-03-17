cmake_minimum_required(VERSION 3.14)

# Catch2 setup
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
endif()

enable_testing()

include_directories(${CMAKE_SOURCE_DIR}/include)

# Test executable
add_executable(jose_tests
    test_backend_factory.cpp
    test_base64url.cpp
    test_jwk.cpp
    test_jwa.cpp
    test_jws.cpp
    test_jwe.cpp
    test_jwt.cpp
    test_jwk_thumbprint.cpp
    test_rfc7520_examples.cpp
    test_endian.cpp
    test_concat_kdf.cpp
)

if(JOSE_BACKEND STREQUAL "CNG")
    target_sources(jose_tests PRIVATE
        test_cng_base64.cpp
        test_cng_generate_key.cpp
    )
endif()

target_link_libraries(jose_tests
    jose
    nlohmann_json::nlohmann_json
    Catch2::Catch2WithMain
)

include(CTest)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(jose_tests)
