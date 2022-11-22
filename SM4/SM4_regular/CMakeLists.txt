cmake_minimum_required(VERSION 3.23)
project(SM4_regular C)

set(CMAKE_C_STANDARD 99)

add_executable(SM4_regular sm4.h sm4.c)
