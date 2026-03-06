cmake_minimum_required(VERSION 3.14)
project(cpp-jose VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)

# Set default backend based on platform
if(WIN32)
    set(JOSE_BACKEND "CNG" CACHE STRING "Crypto backend: CNG or OpenSSL" FORCE)
else()
    set(JOSE_BACKEND "OpenSSL" CACHE STRING "Crypto backend: CNG or OpenSSL" FORCE)
endif()

# Allow override
option(JOSE_BACKEND "Crypto backend: CNG or OpenSSL" ${JOSE_BACKEND})

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
#    src/jwa.cpp
#    src/jws.cpp
#    src/jwe.cpp
#    src/jwt.cpp
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
