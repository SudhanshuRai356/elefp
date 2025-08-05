cmake_minimum_required(VERSION 3.16)
project(elefp LANGUAGES CXX)
# Setting the C++ standards
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Openssl required
find_package(OpenSSL REQUIRED)
# directories to be included
include_directories(include external/liboqs/build/include)
# source files
set(SRC_FILES
    src/crypto/AesGcm.cpp
    src/crypto/HKDF.cpp
    src/crypto/KeyExchange.cpp
)
# test execs
add_executable(test_kem
    test/test_kem.cpp
    ${SRC_FILES}
)
# Link with liboqs and OpenSSL
target_link_libraries(test_kem
    ${CMAKE_SOURCE_DIR}/external/liboqs/build/lib/liboqs.a
    OpenSSL::SSL
    OpenSSL::Crypto
)
