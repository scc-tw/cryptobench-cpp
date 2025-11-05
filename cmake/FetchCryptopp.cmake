# FetchCryptopp.cmake - Fetch and configure Crypto++ 8.9.0
#
# Crypto++ is a comprehensive C++ cryptographic library

include(FetchContent)
include(ExternalProject)

message(STATUS "Fetching Crypto++ 8.9.0...")

# Clone or update Crypto++
FetchContent_Declare(
    cryptopp_src
    GIT_REPOSITORY https://github.com/weidai11/cryptopp.git
    GIT_TAG        CRYPTOPP_8_9_0  # Version 8.9.0
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(cryptopp_src)
set(CRYPTOPP_SOURCE_DIR ${cryptopp_src_SOURCE_DIR})

# Build Crypto++ using its Makefile
# For simplicity, let's use Crypto++'s default optimizations which are already good
if(APPLE)
    set(CRYPTOPP_MAKE_TARGET "")
else()
    set(CRYPTOPP_MAKE_TARGET "static")
endif()

# WARNING SUPPRESSION FOR CRYPTO++ BUILD ISSUES
# 
# SECURITY CONCERN: The following warning suppressions are needed due to
# GCC's -Wstringop-overflow detection in Crypto++ 8.9.0 code:
#
# Error: 'void* __builtin_memcpy(void*, const void*, long unsigned int)' 
#        specified bound 18446744073709551612 exceeds maximum object size
#        in esign.cpp:115:14 (InvertibleESIGNFunction::GenerateRandom)
#
# INVESTIGATION NEEDED:
# 1. Is this a FALSE POSITIVE in GCC's static analysis?
# 2. Is this a REAL BUFFER OVERFLOW vulnerability in Crypto++ 8.9.0?
# 3. Should this be reported as a potential CVE?
#
# The suspicious bound value (18446744073709551612 = 0xFFFFFFFFFFFFFFFC)
# suggests this might be related to:
# - Integer underflow (-4 cast to size_t)
# - Pointer arithmetic error
# - Uninitialized variable being used as size
#
# ACTION ITEMS:
# - [ ] Test with Crypto++ latest version (8.9.1+) when available
# - [ ] Report to Crypto++ maintainers if confirmed as real issue
# - [ ] Consider switching to different crypto library if vulnerability confirmed
# - [ ] Monitor CVE databases for related Crypto++ vulnerabilities
#
# TEMPORARY MITIGATION:
# Suppressing warnings to allow benchmarking, but this should NOT be used
# in production code without thorough security review.

set(CRYPTOPP_WARNING_FLAGS "")
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(CRYPTOPP_WARNING_FLAGS "-Wno-stringop-overflow -Wno-array-bounds -Wno-stringop-overread -Wno-maybe-uninitialized")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CRYPTOPP_WARNING_FLAGS "-Wno-array-bounds -Wno-uninitialized")
endif()

if(WIN32)
    # Use CMake-based build for Crypto++ on Windows to avoid path/space issues with GNUmakefile
    set(CRYPTOPP_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/cryptopp-build)
    ExternalProject_Add(
        cryptopp_external
        SOURCE_DIR ${CRYPTOPP_SOURCE_DIR}
        BINARY_DIR ${CRYPTOPP_BUILD_DIR}
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DBUILD_TESTING=OFF
            -DBUILD_SHARED=OFF
            -DBUILD_STATIC=ON
        BUILD_COMMAND ${CMAKE_COMMAND} --build ${CRYPTOPP_BUILD_DIR} --config Release
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS
            ${CRYPTOPP_BUILD_DIR}/Release/cryptopp-static.lib
            ${CRYPTOPP_BUILD_DIR}/Release/cryptopp.lib
    )

    add_library(cryptopp::cryptopp STATIC IMPORTED GLOBAL)
    # Prefer the static target name used by Crypto++ CMake
    set_target_properties(cryptopp::cryptopp PROPERTIES
        IMPORTED_LOCATION ${CRYPTOPP_BUILD_DIR}/Release/cryptopp-static.lib
        INTERFACE_INCLUDE_DIRECTORIES ${CRYPTOPP_SOURCE_DIR}
    )
    add_dependencies(cryptopp::cryptopp cryptopp_external)
else()
    # Create custom target to build Crypto++ with GNU make
    add_custom_command(
        OUTPUT ${CRYPTOPP_SOURCE_DIR}/libcryptopp.a
        COMMAND ${CMAKE_COMMAND} -E env 
            CXX=${CMAKE_CXX_COMPILER}
            CC=${CMAKE_C_COMPILER}
            CXXFLAGS="-DNDEBUG -O3 -fPIC -march=native -mtune=native -fomit-frame-pointer -funroll-loops ${CRYPTOPP_WARNING_FLAGS}"
            make -j${CMAKE_BUILD_PARALLEL_LEVEL} ${CRYPTOPP_MAKE_TARGET}
        WORKING_DIRECTORY ${CRYPTOPP_SOURCE_DIR}
        COMMENT "Building Crypto++ 8.9.0..."
        VERBATIM
    )

    add_custom_target(cryptopp_build ALL
        DEPENDS ${CRYPTOPP_SOURCE_DIR}/libcryptopp.a
    )

    # Create imported target for Crypto++
    add_library(cryptopp::cryptopp STATIC IMPORTED GLOBAL)
    set_target_properties(cryptopp::cryptopp PROPERTIES
        IMPORTED_LOCATION ${CRYPTOPP_SOURCE_DIR}/libcryptopp.a
        INTERFACE_INCLUDE_DIRECTORIES ${CRYPTOPP_SOURCE_DIR}
    )

    # Make sure the library is built before it's used
    add_dependencies(cryptopp::cryptopp cryptopp_build)
endif()

message(STATUS "Crypto++ 8.9.0 configured successfully")