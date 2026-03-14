cmake_minimum_required(VERSION 3.14)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(jose_cli jose.cpp)
set_target_properties(jose_cli PROPERTIES OUTPUT_NAME jose)
target_link_libraries(jose_cli jose nlohmann_json::nlohmann_json)

install(TARGETS jose_cli
    RUNTIME DESTINATION bin
)
