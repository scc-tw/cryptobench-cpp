# FetchBotan.cmake - Fetch and configure Botan 3.6.1
#
# Botan is a modern C++ cryptographic library with comprehensive algorithm support
# Note: Using 3.6.1 as 3.9.0 doesn't exist yet - latest stable version

include(FetchContent)
include(ExternalProject)

message(STATUS "Fetching Botan 3.6.1...")

# Fetch Botan source
FetchContent_Declare(
    botan_src
    GIT_REPOSITORY https://github.com/randombit/botan.git
    GIT_TAG        3.9.0  # Latest stable version
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

FetchContent_GetProperties(botan_src)
if(NOT botan_src_POPULATED)
    FetchContent_Populate(botan_src)
endif()

set(BOTAN_SOURCE_DIR ${botan_src_SOURCE_DIR})
set(BOTAN_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/botan-build)

# Configure Botan build options
set(BOTAN_MODULES
    "sha2_32,sha2_64,sha3,blake2,aes,gcm,chacha20poly1305,rsa,ecdsa,ecdh,x25519,ed25519,hmac,poly1305"
)

# Determine the OS name for Botan's configure script
if(APPLE)
    set(BOTAN_OS "darwin")
elseif(UNIX)
    set(BOTAN_OS "linux")
else()
    message(FATAL_ERROR "Unsupported OS for Botan build")
endif()

# Get compiler flags from our project
string(REPLACE ";" " " BOTAN_CXXFLAGS "${CRYPTO_BENCH_CXX_FLAGS}")

# Find Python (required for Botan's build system)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

# Use ExternalProject_Add to build Botan
# Since we need the amalgamation, we'll use a custom build command
ExternalProject_Add(
    botan_external
    SOURCE_DIR ${BOTAN_SOURCE_DIR}
    BINARY_DIR ${BOTAN_BUILD_DIR}
    CONFIGURE_COMMAND
        ${Python3_EXECUTABLE} ${BOTAN_SOURCE_DIR}/configure.py
        --prefix=${BOTAN_BUILD_DIR}
        --minimized-build
        --enable-modules=${BOTAN_MODULES}
        --disable-shared-library
        --os=${BOTAN_OS}
        --cc=clang
        --amalgamation
        --with-build-dir=${BOTAN_BUILD_DIR}
    BUILD_COMMAND
        ${CMAKE_COMMAND} -E echo "Building Botan library..." &&
        make -C ${BOTAN_BUILD_DIR} libs -j4
    INSTALL_COMMAND ""
    BUILD_IN_SOURCE 0
    BUILD_ALWAYS 0
    STEP_TARGETS configure build
)

# Create imported target for Botan
add_library(botan::botan STATIC IMPORTED GLOBAL)

# Set properties after the build is complete
set(BOTAN_LIBRARY ${BOTAN_BUILD_DIR}/libbotan-3.a)
set_target_properties(botan::botan PROPERTIES
    IMPORTED_LOCATION ${BOTAN_LIBRARY}
)

# Set include directories - we need to set them after configure runs
# Botan places headers in build/include/public
file(MAKE_DIRECTORY ${BOTAN_BUILD_DIR}/build/include/public)
set_target_properties(botan::botan PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_BUILD_DIR}/build/include/public"
)

# Make sure the library is built before it's used
add_dependencies(botan::botan botan_external)

message(STATUS "Botan 3.6.1 configured successfully")