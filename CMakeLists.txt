cmake_minimum_required(VERSION 3.16)
project(crypto-bench
    VERSION 1.0.0
    DESCRIPTION "Comprehensive C++ Cryptographic Library Benchmarking Suite"
    LANGUAGES CXX C)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Platform detection
if(APPLE)
    set(PLATFORM_MACOS TRUE)
elseif(UNIX)
    set(PLATFORM_LINUX TRUE)
elseif(WIN32)
    set(PLATFORM_WINDOWS TRUE)
endif()

# Build options for library selection
option(BUILD_CRYPTOPP "Build and benchmark Crypto++ 8.9.0" ON)
option(BUILD_OPENSSL "Build and benchmark OpenSSL 3.6.0" ON)
option(BUILD_BOTAN "Build and benchmark Botan 3.9.0" ON)
option(BUILD_LIBSODIUM "Build and benchmark libsodium 1.0.20" ON)
option(BUILD_MBEDTLS "Build and benchmark mbedTLS 4.0.0" ON)

# Optimization options
option(ENABLE_LTO "Enable Link-Time Optimization" ON)
option(ENABLE_PGO "Enable Profile-Guided Optimization" OFF)
option(ENABLE_NATIVE "Enable CPU-specific optimizations" ON)

# PGO phase control
if(ENABLE_PGO)
    set(PGO_PHASE "GENERATE" CACHE STRING "PGO phase: GENERATE or USE")
    set_property(CACHE PGO_PHASE PROPERTY STRINGS "GENERATE" "USE")
endif()

# Include compiler flags configuration
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompilerFlags.cmake)

# Set up FetchContent for dependency management
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# Fetch Google Benchmark (always needed)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchGoogleBench.cmake)

# Conditionally fetch cryptographic libraries
if(BUILD_CRYPTOPP)
    message(STATUS "Crypto++ benchmarks enabled")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchCryptopp.cmake)
endif()

if(BUILD_OPENSSL)
    message(STATUS "OpenSSL benchmarks enabled")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchOpenSSL.cmake)
endif()

if(BUILD_BOTAN)
    message(STATUS "Botan benchmarks enabled")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchBotan.cmake)
endif()

if(BUILD_LIBSODIUM)
    message(STATUS "libsodium benchmarks enabled")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchLibsodium.cmake)
endif()

if(BUILD_MBEDTLS)
    message(STATUS "mbedTLS benchmarks enabled")
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FetchMbedTLS.cmake)
endif()

# Check that at least one library is enabled
if(NOT BUILD_CRYPTOPP AND NOT BUILD_OPENSSL AND NOT BUILD_BOTAN AND
   NOT BUILD_LIBSODIUM AND NOT BUILD_MBEDTLS)
    message(FATAL_ERROR "At least one cryptographic library must be enabled")
endif()

# Define preprocessor macros for enabled libraries
set(CRYPTO_BENCH_DEFINES "")
if(BUILD_CRYPTOPP)
    list(APPEND CRYPTO_BENCH_DEFINES ENABLE_CRYPTOPP)
endif()
if(BUILD_OPENSSL)
    list(APPEND CRYPTO_BENCH_DEFINES ENABLE_OPENSSL)
endif()
if(BUILD_BOTAN)
    list(APPEND CRYPTO_BENCH_DEFINES ENABLE_BOTAN)
endif()
if(BUILD_LIBSODIUM)
    list(APPEND CRYPTO_BENCH_DEFINES ENABLE_LIBSODIUM)
endif()
if(BUILD_MBEDTLS)
    list(APPEND CRYPTO_BENCH_DEFINES ENABLE_MBEDTLS)
endif()

# Add source directory
add_subdirectory(src)

# Print configuration summary
message(STATUS "")
message(STATUS "========================================")
message(STATUS "crypto-bench Configuration Summary")
message(STATUS "========================================")
message(STATUS "Build type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ compiler:         ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ flags:            ${CMAKE_CXX_FLAGS}")
message(STATUS "")
message(STATUS "Libraries enabled:")
message(STATUS "  Crypto++:           ${BUILD_CRYPTOPP}")
message(STATUS "  OpenSSL:            ${BUILD_OPENSSL}")
message(STATUS "  Botan:              ${BUILD_BOTAN}")
message(STATUS "  libsodium:          ${BUILD_LIBSODIUM}")
message(STATUS "  mbedTLS:            ${BUILD_MBEDTLS}")
message(STATUS "")
message(STATUS "Optimizations:")
message(STATUS "  Link-Time Opt:      ${ENABLE_LTO}")
message(STATUS "  Profile-Guided:     ${ENABLE_PGO}")
if(ENABLE_PGO)
    message(STATUS "  PGO Phase:          ${PGO_PHASE}")
endif()
message(STATUS "  Native CPU:         ${ENABLE_NATIVE}")
message(STATUS "========================================")
message(STATUS "")