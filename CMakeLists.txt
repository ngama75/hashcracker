cmake_minimum_required(VERSION 3.15)
project(hashcracker)

set(CMAKE_CXX_STANDARD 17)

find_library(MBEDCRYPTO mbedcrypto REQUIRED)
find_library(JSON11 json11 REQUIRED)
message(STATUS "json11 library found: ${JSON11}")
message(STATUS "mbedtls library found: ${MBEDCRYPTO}")

add_executable(hashcracker main.cpp)
target_link_libraries(hashcracker ${JSON11} ${MBEDCRYPTO})
install(TARGETS hashcracker DESTINATION bin)
