cmake_minimum_required(VERSION 3.23)
project(untitled)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_executable(untitled main.cpp)
target_link_libraries(untitled libgmp.a libssl.a)