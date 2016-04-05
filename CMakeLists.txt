cmake_minimum_required(VERSION 3.3)
project(encryptutils)

find_library(LIBCRYPTO crypto)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-deprecated-declarations")

set(SOURCE_FILES encryptutils.cpp testencrypt.cpp)
add_executable(encryptutils ${SOURCE_FILES})
target_link_libraries(encryptutils ${LIBCRYPTO})