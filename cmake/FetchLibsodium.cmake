# FetchLibsodium.cmake - Fetch and configure libsodium 1.0.20
#
# libsodium is a modern, easy-to-use crypto library for network communication,
# encryption, decryption, signatures, password hashing and more

include(FetchContent)

message(STATUS "Fetching libsodium 1.0.20...")

# Fetch libsodium source
FetchContent_Declare(
    libsodium_src
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.20-RELEASE  # Version 1.0.20
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Configure libsodium build options
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "")
set(SODIUM_MINIMAL ON CACHE BOOL "")  # Minimal build for benchmarking
set(SODIUM_STATIC ON CACHE BOOL "")   # Static library only

# Make libsodium available
FetchContent_MakeAvailable(libsodium_src)

# The libsodium CMake creates the target: sodium
if(TARGET sodium)
    message(STATUS "libsodium 1.0.20 configured successfully")

    # Apply our optimization flags to libsodium target
    target_compile_options(sodium PRIVATE ${CRYPTO_BENCH_C_FLAGS})

    # Create alias target for easier access
    add_library(libsodium::sodium ALIAS sodium)
    
    # Set properties for better integration
    set_target_properties(sodium PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
else()
    message(FATAL_ERROR "Failed to configure libsodium - sodium target not found")
endif()

message(STATUS "libsodium 1.0.20 configured successfully")