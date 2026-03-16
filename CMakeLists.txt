cmake_minimum_required(VERSION 3.16)
project(elefp LANGUAGES CXX)

# Setting the C++ standards
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable debugging symbols
set(CMAKE_BUILD_TYPE Debug)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Find ASIO (header-only library)
find_path(ASIO_INCLUDE_DIR asio.hpp)
if(NOT ASIO_INCLUDE_DIR)
    # If not found, use system package or download
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(ASIO QUIET asio)
    endif()
    if(NOT ASIO_FOUND)
        message(STATUS "ASIO not found, using fallback include path")
        set(ASIO_INCLUDE_DIR "/usr/include")
    endif()
endif()

# Crypto library
add_library(crypto 
    src/crypto/AesGcm.cpp 
    src/crypto/HKDF.cpp 
    src/crypto/KeyExchange.cpp
)

target_include_directories(crypto PUBLIC 
    ${CMAKE_SOURCE_DIR}/include 
    ${CMAKE_SOURCE_DIR}/external/liboqs/build/include
)

target_link_libraries(crypto PRIVATE 
    ${CMAKE_SOURCE_DIR}/external/liboqs/build/lib/liboqs.a 
    OpenSSL::SSL 
    OpenSSL::Crypto
)

# Transport library
add_library(transport 
    src/transport/TransportUtil.cpp 
    src/transport/SecureSession.cpp 
    src/transport/SessionManager.cpp
)

target_include_directories(transport PUBLIC 
    ${CMAKE_SOURCE_DIR}/include 
    ${CMAKE_SOURCE_DIR}/external/liboqs/build/include
)

target_link_libraries(transport PRIVATE crypto)

# VPN library  
add_library(vpn
    src/vpn/TunInterface.cpp
    src/vpn/IpPool.cpp
    src/vpn/PacketRouter.cpp
    src/vpn/VpnServer.cpp
    src/vpn/VpnClient.cpp
    src/vpn/ConfigManager.cpp
)

target_include_directories(vpn PUBLIC 
    ${CMAKE_SOURCE_DIR}/include
    ${ASIO_INCLUDE_DIR}
)

target_link_libraries(vpn PUBLIC 
    transport 
    crypto 
    Threads::Threads
)

# VPN Server executable
add_executable(vpn_server
    src/vpn_server_main.cpp
)

target_include_directories(vpn_server PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(vpn_server PRIVATE vpn transport crypto)

# VPN Client executable  
add_executable(vpn_client
    src/vpn_client_main.cpp
)

target_include_directories(vpn_client PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(vpn_client PRIVATE vpn transport crypto)

# Legacy test executables
add_executable(test_kem test/test_kem.cpp)
target_link_libraries(test_kem PRIVATE crypto)

add_executable(crypto_test test/crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE crypto)

add_executable(udp_server test/udp_server.cpp)
target_include_directories(udp_server PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(udp_server PRIVATE transport crypto)

add_executable(udp_client test/udp_client.cpp)
target_include_directories(udp_client PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(udp_client PRIVATE transport crypto)

add_executable(multlead_test test/multlead_test.cpp)
target_link_libraries(multlead_test PRIVATE transport crypto)

# VPN test executables
add_executable(vpn_component_test test/vpn_component_test.cpp)
target_link_libraries(vpn_component_test PRIVATE vpn transport crypto)

add_executable(vpn_integration_test test/vpn_integration_test.cpp)
target_include_directories(vpn_integration_test PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(vpn_integration_test PRIVATE vpn transport crypto)

add_executable(dilithium_test test/dilithium_test.cpp)
target_link_libraries(dilithium_test PRIVATE transport crypto)

# Install targets
install(TARGETS vpn_server vpn_client 
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ 
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

# CTEST integration
enable_testing()
add_test(NAME TestKem COMMAND test_kem)
add_test(NAME CryptoUnit COMMAND crypto_test)
add_test(NAME VpnComponents COMMAND vpn_component_test)
add_test(NAME VpnIntegration COMMAND vpn_integration_test)
add_test(NAME DilithiumTest COMMAND dilithium_test)

# Custom targets for convenience
add_custom_target(run-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS crypto_test test_kem vpn_component_test vpn_integration_test dilithium_test
)

add_custom_target(install-vpn
    COMMAND ${CMAKE_COMMAND} --build . --target install
    DEPENDS vpn_server vpn_client
)
