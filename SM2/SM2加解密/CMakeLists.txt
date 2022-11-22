cmake_minimum_required(VERSION 3.23)
project(untitled C)

set(CMAKE_C_STANDARD 99)

include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(SM2_ENC.c SM2_ENC.h SM2_ENC.c)
