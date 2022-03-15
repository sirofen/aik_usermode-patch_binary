cmake_minimum_required(VERSION 3.21)
project(patch_binary)

set(CMAKE_CXX_STANDARD 20)

option(PATCH_BINARY_INSTALL "Build awaken-discord examples" ON)

add_executable(patch_binary main.cpp)

if (PATCH_BINARY_INSTALL)
install(TARGETS patch_binary DESTINATION bin)
endif()