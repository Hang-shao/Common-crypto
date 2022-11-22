cmake_minimum_required(VERSION 3.23)
project(SM9_Key_encap C)

set(CMAKE_C_STANDARD 99)
SET(CMAKE_BUILD_TYPE Debug)

include_directories(${PROJECT_SOURCE_DIR}/include)
link_libraries(${PROJECT_SOURCE_DIR}/lib/miracl.a)

add_executable(SM9_Key_encap SM9_Key_encap.h SM9_Key_encap.c)
#add_executable(sm9_exchange_key main.c)