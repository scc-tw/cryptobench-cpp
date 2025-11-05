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

FetchContent_MakeAvailable(libsodium_src)

# Set up paths
set(LIBSODIUM_SOURCE_DIR ${libsodium_src_SOURCE_DIR})
set(LIBSODIUM_BINARY_DIR ${libsodium_src_BINARY_DIR})
set(LIBSODIUM_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/libsodium_install)

if(WIN32)
    # Use CMake-based build on Windows (Autotools configure is not available)
    ExternalProject_Add(
        libsodium_build
        SOURCE_DIR ${LIBSODIUM_SOURCE_DIR}
        BINARY_DIR ${LIBSODIUM_BINARY_DIR}
        INSTALL_DIR ${LIBSODIUM_INSTALL_DIR}
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${LIBSODIUM_SOURCE_DIR} -B ${LIBSODIUM_BINARY_DIR}
            -DBUILD_SHARED_LIBS=OFF
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_INSTALL_PREFIX=${LIBSODIUM_INSTALL_DIR}
        BUILD_COMMAND ${CMAKE_COMMAND} --build ${LIBSODIUM_BINARY_DIR} --config Release --target install
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS
            ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.lib
            ${LIBSODIUM_INSTALL_DIR}/include/sodium.h
    )
else()
    # Build libsodium using Autotools on Unix-like systems
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
endif()

# Create a function to set up libsodium imported target
function(setup_libsodium_targets)
    # Ensure the install directory exists
    file(MAKE_DIRECTORY "${LIBSODIUM_INSTALL_DIR}/include")
    
    # Create imported target for libsodium
    add_library(sodium STATIC IMPORTED GLOBAL)
    add_dependencies(sodium libsodium_build)

    # Set properties for the imported target
    if(WIN32)
        set_target_properties(sodium PROPERTIES
            IMPORTED_LOCATION ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.lib
            INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_INSTALL_DIR}/include
            POSITION_INDEPENDENT_CODE ON
        )
    else()
        set_target_properties(sodium PROPERTIES
            IMPORTED_LOCATION ${LIBSODIUM_INSTALL_DIR}/lib/libsodium.a
            INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_INSTALL_DIR}/include
            POSITION_INDEPENDENT_CODE ON
        )
    endif()

    # Create alias target for consistent naming
    add_library(libsodium::sodium ALIAS sodium)
endfunction()

# Set up the targets immediately
setup_libsodium_targets()

message(STATUS "libsodium 1.0.20 configured successfully")