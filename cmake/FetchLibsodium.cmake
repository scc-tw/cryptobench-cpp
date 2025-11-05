# FetchLibsodium.cmake - Fetch and build libsodium 1.0.20
#
# This module fetches libsodium from the official repository and builds it
# with the same compiler optimizations as the rest of the project.

include(FetchContent)

message(STATUS "Fetching libsodium 1.0.20...")

FetchContent_Declare(
    libsodium_src
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.20-RELEASE
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(libsodium_src)

# libsodium uses autotools, so we need to build it manually
set(LIBSODIUM_SOURCE_DIR ${libsodium_src_SOURCE_DIR})
set(LIBSODIUM_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/libsodium-build)
set(LIBSODIUM_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/libsodium-install)

# Create build and install directories
file(MAKE_DIRECTORY ${LIBSODIUM_BINARY_DIR})
file(MAKE_DIRECTORY ${LIBSODIUM_INSTALL_DIR})

# Get compiler flags for consistent optimization
get_property(COMPILE_FLAGS GLOBAL PROPERTY CRYPTO_BENCH_COMPILE_FLAGS)
string(REPLACE ";" " " COMPILE_FLAGS_STR "${COMPILE_FLAGS}")

# Configure libsodium with our optimization flags
set(LIBSODIUM_CONFIGURE_COMMAND
    ${LIBSODIUM_SOURCE_DIR}/configure
    --prefix=${LIBSODIUM_INSTALL_DIR}
    --enable-static
    --disable-shared
    --disable-dependency-tracking
    --enable-minimal
    CC=${CMAKE_C_COMPILER}
    CXX=${CMAKE_CXX_COMPILER}
    CFLAGS=${COMPILE_FLAGS_STR}
    CXXFLAGS=${COMPILE_FLAGS_STR}
)

# Build libsodium
add_custom_command(
    OUTPUT ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
    COMMAND cd ${LIBSODIUM_SOURCE_DIR} && ./autogen.sh
    COMMAND cd ${LIBSODIUM_BINARY_DIR} && ${LIBSODIUM_CONFIGURE_COMMAND}
    COMMAND cd ${LIBSODIUM_BINARY_DIR} && ${CMAKE_MAKE_PROGRAM} -j${CMAKE_BUILD_PARALLEL_LEVEL}
    COMMAND cd ${LIBSODIUM_BINARY_DIR} && ${CMAKE_MAKE_PROGRAM} install
    DEPENDS ${libsodium_src_SOURCE_DIR}/configure.ac
    WORKING_DIRECTORY ${LIBSODIUM_BINARY_DIR}
    COMMENT "Building libsodium 1.0.20 with optimizations"
    VERBATIM
)

# Create libsodium target
add_custom_target(libsodium_build
    DEPENDS ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
)

# Create imported library target
add_library(libsodium STATIC IMPORTED)
set_target_properties(libsodium PROPERTIES
    IMPORTED_LOCATION ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_INSTALL_DIR}/include
)

# Make sure libsodium is built before it's used
add_dependencies(libsodium libsodium_build)

# Export variables for use in main CMakeLists.txt
set(LIBSODIUM_FOUND TRUE CACHE BOOL "libsodium found")
set(LIBSODIUM_INCLUDE_DIRS ${LIBSODIUM_INSTALL_DIR}/include CACHE PATH "libsodium include directory")
set(LIBSODIUM_LIBRARIES ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a CACHE FILEPATH "libsodium library")

message(STATUS "libsodium 1.0.20 will be built from source with optimizations")
message(STATUS "libsodium include dir: ${LIBSODIUM_INCLUDE_DIRS}")
message(STATUS "libsodium library: ${LIBSODIUM_LIBRARIES}")