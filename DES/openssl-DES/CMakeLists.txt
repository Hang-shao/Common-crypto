cmake_minimum_required(VERSION 3.23)
project(openssl_DES)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_OSX_ARCHITECTURES "arm64")

INCLUDE_DIRECTORIES(/usr/local/include)
LINK_DIRECTORIES(/usr/local/lib/)

add_executable(openssl_DES main.cpp )
target_link_libraries(openssl_DES libssl.a libcrypto.a)