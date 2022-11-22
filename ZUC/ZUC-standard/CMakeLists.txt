cmake_minimum_required(VERSION 3.23)
project(ZUC_standard C)

set(CMAKE_C_STANDARD 99)

add_executable(ZUC_standard main.c zuc.h)
