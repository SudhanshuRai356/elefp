cmake_minimum_required(VERSION 3.16)
project(elefp LANGUAGES CXX)
# Setting the C++ standards
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Openssl required
find_package(OpenSSL REQUIRED)
# add crypto libs
add_library(crypto src/crypto/AesGcm.cpp src/crypto/HKDF.cpp src/crypto/KeyExchange.cpp)
#libraries to be included
target_include_directories(crypto PUBLIC ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external/liboqs/build/include)
#libraries to be linked
target_link_libraries(crypto PRIVATE ${CMAKE_SOURCE_DIR}/external/liboqs/build/lib/liboqs.a OpenSSL::SSL OpenSSL::Crypto)
# test execs
add_executable(test_kem
    test/test_kem.cpp
)
target_link_libraries(test_kem
    PRIVATE crypto
)
add_executable(crypto_test
    test/crypto_test.cpp
)
target_link_libraries(crypto_test
    PRIVATE crypto
)
#CTEST integration
enable_testing()
add_test(NAME TestKem COMMAND test_kem)
add_test(NAME CryptoUnit COMMAND crypto_test)