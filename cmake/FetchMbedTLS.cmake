# FetchMbedTLS.cmake - Fetch and configure mbedTLS 4.0.0
#
# mbedTLS (now Mbed TLS) is a lightweight cryptographic library designed for embedded systems

include(FetchContent)

message(STATUS "Fetching mbedTLS 4.0.0...")

# Disable SSL verification for faster downloads
set(GIT_SSL_NO_VERIFY 1)
set(CMAKE_TLS_VERIFY FALSE)

# Fetch mbedTLS source using Git (includes submodules)
FetchContent_Declare(
    mbedtls_src
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v4.0.0
    GIT_SHALLOW    FALSE  # Need full clone for submodules
    GIT_PROGRESS   TRUE
)

# Configure mbedTLS build options
set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "")
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "")

# Disable unnecessary features to speed up build
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "")

# Make mbedTLS available
FetchContent_MakeAvailable(mbedtls_src)

# The mbedTLS CMake creates these targets:
# - mbedcrypto (cryptographic primitives)
# - mbedx509 (X.509 certificate handling)
# - mbedtls (TLS/SSL)

# We mainly need mbedcrypto for hash functions
if(TARGET mbedcrypto)
    message(STATUS "mbedTLS 4.0.0 configured successfully")

    # Apply our optimization flags to mbedTLS targets
    target_compile_options(mbedcrypto PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})
    target_compile_options(mbedx509 PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})
    target_compile_options(mbedtls PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})

    # Create alias targets for easier access
    add_library(MbedTLS::mbedcrypto ALIAS mbedcrypto)
    add_library(MbedTLS::mbedx509 ALIAS mbedx509)
    add_library(MbedTLS::mbedtls ALIAS mbedtls)
else()
    message(FATAL_ERROR "Failed to configure mbedTLS - mbedcrypto target not found")
endif()