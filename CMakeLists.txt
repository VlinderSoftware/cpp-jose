cmake_minimum_required(VERSION 3.14)
project(cpp-jose VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(BUILD_CLI "Build jose CLI tool" ON)
set(JOSE_RSA_GENERATION_MAX_ATTEMPTS "8" CACHE STRING "Maximum attempts for RSA key generation/export hardening")

if(NOT JOSE_RSA_GENERATION_MAX_ATTEMPTS MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "JOSE_RSA_GENERATION_MAX_ATTEMPTS must be a positive integer")
endif()

# Set default backend based on platform
if(WIN32)
    set(_jose_backend_default "CNG")
else()
    set(_jose_backend_default "OpenSSL")
endif()

# Allow override from cache/CLI (for example: -DJOSE_BACKEND=OpenSSL)
set(JOSE_BACKEND "${_jose_backend_default}" CACHE STRING "Crypto backend: CNG or OpenSSL")
set_property(CACHE JOSE_BACKEND PROPERTY STRINGS "CNG" "OpenSSL")

if(NOT JOSE_BACKEND STREQUAL "CNG" AND NOT JOSE_BACKEND STREQUAL "OpenSSL")
    message(FATAL_ERROR "Invalid JOSE_BACKEND='${JOSE_BACKEND}'. Valid values are: CNG, OpenSSL")
endif()

if(JOSE_BACKEND STREQUAL "CNG" AND NOT WIN32)
    message(FATAL_ERROR "JOSE_BACKEND=CNG is only supported on Windows")
endif()

# Fetch nlohmann/json
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

if(JOSE_BACKEND STREQUAL "OpenSSL")
    find_package(OpenSSL REQUIRED)
    add_definitions(-DJOSE_USE_OPENSSL)
else()
    # CNG backend
    add_definitions(-DJOSE_USE_CNG)
    set(CMAKE_REQUIRED_LIBRARIES bcrypt)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/jose)

# Source files
set(JOSE_SOURCES
    src/jwk.cpp
    src/jwa.cpp
    src/jws.cpp
    src/jwe.cpp
    src/jwt.cpp
    src/jwk_set.cpp
    src/jwk_thumbprint.cpp
    "src/private/back_end.cpp"
    src/base64url.cpp
    "src/private/back_end_factory.cpp"
    
)

if(JOSE_BACKEND STREQUAL "OpenSSL")
    list(APPEND JOSE_SOURCES src/private/openssl_back_end.cpp)
endif()

if(JOSE_BACKEND STREQUAL "CNG")
    list(APPEND JOSE_SOURCES src/private/cng_back_end.cpp)
endif()

# Create library
add_library(jose ${JOSE_SOURCES})

target_compile_definitions(jose PRIVATE JOSE_RSA_GENERATION_MAX_ATTEMPTS=${JOSE_RSA_GENERATION_MAX_ATTEMPTS})

if(JOSE_BACKEND STREQUAL "OpenSSL")
    target_link_libraries(jose OpenSSL::SSL OpenSSL::Crypto nlohmann_json)
else()
    target_link_libraries(jose bcrypt nlohmann_json)
endif()

## Enable testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES)
   add_subdirectory(examples)
endif()

# CLI tool
if(BUILD_CLI)
    add_subdirectory(cli)
endif()

# Installation
install(TARGETS jose
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/jose
    DESTINATION include
)

# Commented out export due to nlohmann_json dependency issue
# install(EXPORT joseTargets
#     FILE joseTargets.cmake
#     NAMESPACE jose::
#     DESTINATION lib/cmake/jose
# )
