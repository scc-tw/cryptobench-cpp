# FetchMbedTLS.cmake - Fetch and configure mbedTLS 4.0.0
#
# mbedTLS (now Mbed TLS) is a lightweight cryptographic library designed for embedded systems

include(FetchContent)

message(STATUS "Fetching mbedTLS 4.0.0...")

# Disable SSL verification for faster downloads
set(GIT_SSL_NO_VERIFY 1)
set(CMAKE_TLS_VERIFY FALSE)

# Fetch mbedTLS source using Git (includes submodules)
# Note: mbedTLS 4.0.0 requires recursive submodule initialization for TF-PSA-Crypto
FetchContent_Declare(
    mbedtls_src
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v4.0.0
    GIT_SHALLOW    FALSE  # Need full clone for submodules
    GIT_SUBMODULES_RECURSE TRUE  # Need TF-PSA-Crypto submodule
    GIT_PROGRESS   TRUE
)

# Configure mbedTLS build options BEFORE FetchContent_MakeAvailable
# These need to be set before the mbedTLS project is configured
set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "")
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "")

# Disable unnecessary features to speed up build
set(MBEDTLS_BUILD_TESTS OFF CACHE BOOL "")

# IMPORTANT: mbedTLS 4.0.0 requires Python to generate source files
# The generated files are created during the configuration step
# We need to ensure Python is available before configuring mbedTLS
find_package(Python3 COMPONENTS Interpreter REQUIRED)
if(NOT Python3_FOUND)
    message(FATAL_ERROR "Python 3 is required to build mbedTLS 4.0.0 (for generating source files)")
endif()

# Set the Python executable for mbedTLS to use
set(MBEDTLS_PYTHON_EXECUTABLE ${Python3_EXECUTABLE} CACHE FILEPATH "Python executable for mbedTLS")
set(PYTHON_EXECUTABLE ${Python3_EXECUTABLE} CACHE FILEPATH "Python executable")

# IMPORTANT: For mbedTLS 4.0.0, we need to ensure generated files are created
# The build system expects certain files to be generated during configuration
# Setting this option helps ensure they are generated correctly
set(GEN_FILES ON CACHE BOOL "Generate required source files for mbedTLS")

# Make mbedTLS available - this will run the configuration which generates the required files
FetchContent_MakeAvailable(mbedtls_src)

# The mbedTLS 4.0.0 CMake creates these targets:
# - tfpsacrypto (cryptographic primitives - renamed from mbedcrypto in 4.0)
# - mbedx509 (X.509 certificate handling)
# - mbedtls (TLS/SSL)

# We mainly need tfpsacrypto for cryptographic functions
if(TARGET tfpsacrypto)
    message(STATUS "mbedTLS 4.0.0 configured successfully")

    # Apply our optimization flags to mbedTLS targets
    target_compile_options(tfpsacrypto PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})
    if(TARGET mbedx509)
        target_compile_options(mbedx509 PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})
    endif()
    if(TARGET mbedtls)
        target_compile_options(mbedtls PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})
    endif()

    # Create alias targets for easier access
    # We create both the new name and compatibility name
    add_library(MbedTLS::tfpsacrypto ALIAS tfpsacrypto)
    add_library(MbedTLS::mbedcrypto ALIAS tfpsacrypto)  # Compatibility alias
    if(TARGET mbedx509)
        add_library(MbedTLS::mbedx509 ALIAS mbedx509)
    endif()
    if(TARGET mbedtls)
        add_library(MbedTLS::mbedtls ALIAS mbedtls)
    endif()
else()
    message(FATAL_ERROR "Failed to configure mbedTLS - tfpsacrypto target not found (renamed from mbedcrypto in 4.0.0)")
endif()