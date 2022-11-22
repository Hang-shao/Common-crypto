cmake_minimum_required(VERSION 3.23)
project(sm9_exchange_key C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_BUILD_TYPE Debug)

include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(sm9_exchange_key SM9_Key_ex.c SM9_Key_ex.h)
#add_executable(sm9_exchange_key main.c)