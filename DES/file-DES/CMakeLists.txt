cmake_minimum_required(VERSION 3.23)
project(file_DES)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_OSX_ARCHITECTURES "arm64")

INCLUDE_DIRECTORIES(/usr/local/include)
LINK_DIRECTORIES(/usr/local/lib/)

add_executable(file_DES main2.cpp)
target_link_libraries(file_DES libssl.a libcrypto.a)