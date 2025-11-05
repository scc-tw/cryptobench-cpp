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

FetchContent_GetProperties(cryptopp_src)
if(NOT cryptopp_src_POPULATED)
    FetchContent_Populate(cryptopp_src)
    # After population, the source is in cryptopp_src_SOURCE_DIR
    set(CRYPTOPP_SOURCE_DIR ${cryptopp_src_SOURCE_DIR})
else()
    set(CRYPTOPP_SOURCE_DIR ${cryptopp_src_SOURCE_DIR})
endif()

# Build Crypto++ using its Makefile
# For simplicity, let's use Crypto++'s default optimizations which are already good
if(APPLE)
    set(CRYPTOPP_MAKE_TARGET "")
else()
    set(CRYPTOPP_MAKE_TARGET "static")
endif()

# Create custom target to build Crypto++
# We'll let Crypto++ use its own optimizations (-O3 -march=native is default)
add_custom_command(
    OUTPUT ${CRYPTOPP_SOURCE_DIR}/libcryptopp.a
    COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL} ${CRYPTOPP_MAKE_TARGET}
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

message(STATUS "Crypto++ 8.9.0 configured successfully")