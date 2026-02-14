cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0077 NEW)

project(core_consensus_helper_build LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED BITCOIN_CORE_REPO)
  message(FATAL_ERROR "BITCOIN_CORE_REPO must point to a Bitcoin Core source checkout")
endif()

if(NOT EXISTS "${BITCOIN_CORE_REPO}/CMakeLists.txt")
  message(FATAL_ERROR "BITCOIN_CORE_REPO does not look like a Core source tree: ${BITCOIN_CORE_REPO}")
endif()

# Build only what is required for linking against current Core consensus internals.
set(BUILD_BITCOIN_BIN OFF CACHE BOOL "" FORCE)
set(BUILD_DAEMON OFF CACHE BOOL "" FORCE)
set(BUILD_GUI OFF CACHE BOOL "" FORCE)
set(BUILD_CLI OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_TX OFF CACHE BOOL "" FORCE)
set(BUILD_UTIL OFF CACHE BOOL "" FORCE)
set(BUILD_UTIL_CHAINSTATE OFF CACHE BOOL "" FORCE)
set(BUILD_KERNEL_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_WALLET OFF CACHE BOOL "" FORCE)
set(ENABLE_IPC OFF CACHE BOOL "" FORCE)
set(ENABLE_EXTERNAL_SIGNER OFF CACHE BOOL "" FORCE)
set(WITH_ZMQ OFF CACHE BOOL "" FORCE)
set(WITH_USDT OFF CACHE BOOL "" FORCE)
set(WERROR OFF CACHE BOOL "" FORCE)

add_subdirectory("${BITCOIN_CORE_REPO}" bitcoin-core EXCLUDE_FROM_ALL)

add_executable(core_consensus_helper core_consensus_helper.cpp)
target_include_directories(core_consensus_helper PRIVATE "${BITCOIN_CORE_REPO}/src")
target_link_libraries(core_consensus_helper PRIVATE bitcoin_consensus)
set_target_properties(core_consensus_helper PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
