cmake_minimum_required(VERSION 3.23)
project(SM3_standard C)

set(CMAKE_C_STANDARD 99)

add_executable(SM3_standard main.c sm3.h)
