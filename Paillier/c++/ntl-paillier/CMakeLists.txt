cmake_minimum_required(VERSION 3.23)
project(untitled1)
set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(untitled1 main.cpp paillier.cpp)
target_link_libraries(untitled1 libntl.a libgmp.a libssl.a libcrypto.a)
