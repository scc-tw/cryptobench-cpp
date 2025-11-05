# FetchLibsodium.cmake - Fetch and configure libsodium 1.0.20
#
# libsodium is a modern, easy-to-use crypto library for network communication,
# encryption, decryption, signatures, password hashing and more

include(FetchContent)
include(ExternalProject)

message(STATUS "Fetching libsodium 1.0.20...")

# Fetch libsodium source
FetchContent_Declare(
    libsodium_src
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.20-RELEASE  # Version 1.0.20
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Use the deprecated FetchContent_Populate for now since we need manual build
FetchContent_Populate(libsodium_src)

# Set up paths
set(LIBSODIUM_SOURCE_DIR ${libsodium_src_SOURCE_DIR})
set(LIBSODIUM_BINARY_DIR ${libsodium_src_BINARY_DIR})
set(LIBSODIUM_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/libsodium_install)

# Build libsodium using ExternalProject
ExternalProject_Add(
    libsodium_build
    SOURCE_DIR ${LIBSODIUM_SOURCE_DIR}
    BINARY_DIR ${LIBSODIUM_BINARY_DIR}
    INSTALL_DIR ${LIBSODIUM_INSTALL_DIR}
    CONFIGURE_COMMAND ${LIBSODIUM_SOURCE_DIR}/configure
        --prefix=${LIBSODIUM_INSTALL_DIR}
        --enable-static
        --disable-shared
        --disable-pie
        --disable-ssp
        --with-pic
        CC=${CMAKE_C_COMPILER}
        CFLAGS=${CMAKE_C_FLAGS_RELEASE}
    BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS
        ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
        ${LIBSODIUM_INSTALL_DIR}/include/sodium.h
)

# Create imported target for libsodium
add_library(sodium STATIC IMPORTED GLOBAL)
add_dependencies(sodium libsodium_build)

# Set properties for the imported target
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_INSTALL_DIR}/include
    POSITION_INDEPENDENT_CODE ON
)

# Create alias target for consistent naming
add_library(libsodium::sodium ALIAS sodium)

message(STATUS "libsodium 1.0.20 configured successfully")