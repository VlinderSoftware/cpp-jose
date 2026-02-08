cmake_minimum_required(VERSION 3.14)
project(cpp-jose VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(JOSE_SOURCES
    src/jwk.cpp
    src/jwa.cpp
    src/jws.cpp
    src/jwe.cpp
    src/jwt.cpp
    src/jwk_thumbprint.cpp
    src/base64url.cpp
    src/json_utils.cpp
)

# Create library
add_library(jose ${JOSE_SOURCES})
target_include_directories(jose PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(jose PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Enable testing
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
    EXPORT joseTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/jose
    DESTINATION include
)

install(EXPORT joseTargets
    FILE joseTargets.cmake
    NAMESPACE jose::
    DESTINATION lib/cmake/jose
)
