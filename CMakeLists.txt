cmake_minimum_required(VERSION 3.10)
project(elefp)

set(CMAKE_CXX_STANDARD 17)

# Use the actual header path
include_directories(${CMAKE_SOURCE_DIR}/third_party/liboqs/build/include)

# Add executable
add_executable(guardianvpn src/main.cpp)

# Link liboqs static lib
add_library(oqs STATIC IMPORTED)
set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/third_party/liboqs/build/lib/liboqs.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/third_party/liboqs/build/include
)

target_link_libraries(guardianvpn oqs)

target_link_libraries(guardianvpn
    /home/shura/projects/elefp/third_party/liboqs/build/lib/liboqs.a
    ssl
    crypto
)
