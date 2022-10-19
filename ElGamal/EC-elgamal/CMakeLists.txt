cmake_minimum_required(VERSION 3.23)
project(EC_elgamal C)

set(CMAKE_C_STANDARD 99)

set(INC_DIR "/usr/local/tongsuo-debug/include")
set(LINK_DIR "/usr/local/tongsuo-debug/lib")

include_directories(${INC_DIR})
link_directories(${LINK_DIR})

add_executable(EC_elgamal ec_elgamal_test.c)
#target_link_libraries(EC_elgamal libcrypto.a libssl.a)