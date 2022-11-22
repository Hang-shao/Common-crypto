cmake_minimum_required(VERSION 3.23)
project(SM2_KEY_EX C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_BUILD_TYPE Debug)

include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(SM2_KEY_EX SM2_KEY_EX.c SM2_KEY_EX.h)