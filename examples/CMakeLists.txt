cmake_minimum_required(VERSION 3.14)

# Example programs
add_executable(jwt_example jwt_example.cpp)
target_link_libraries(jwt_example jose nlohmann_json::nlohmann_json)

add_executable(jws_example jws_example.cpp)
target_link_libraries(jws_example jose nlohmann_json::nlohmann_json)

add_executable(jwe_example jwe_example.cpp)
target_link_libraries(jwe_example jose nlohmann_json::nlohmann_json)

add_executable(jwk_example jwk_example.cpp)
target_link_libraries(jwk_example jose nlohmann_json::nlohmann_json)
