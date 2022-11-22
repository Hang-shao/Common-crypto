cmake_minimum_required(VERSION 3.23)
project(SM2_test C)

set(CMAKE_C_STANDARD 99)
include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(SM2_test SM2_sv.h SM2_sv.c)