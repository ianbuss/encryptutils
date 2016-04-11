cmake_minimum_required(VERSION 3.0)
project(encryptutils)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-deprecated-declarations")

include_directories(/usr/local/Cellar/cryptopp/5.6.3_1/include/cryptopp)

find_library(CRYPTOPP cryptopp)

set(SOURCE_FILES encryptutils.cpp testencrypt.cpp)

add_executable(encryptutils ${SOURCE_FILES})

target_link_libraries(encryptutils ${CRYPTOPP})
