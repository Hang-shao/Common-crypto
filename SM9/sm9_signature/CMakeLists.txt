cmake_minimum_required(VERSION 3.23)
project(sm9_signature C)

set(CMAKE_C_STANDARD 99)

include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(sm9_signature SM9_sv.c SM9_sv.h)