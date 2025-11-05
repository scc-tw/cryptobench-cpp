# FetchOpenSSL.cmake - Fetch and configure OpenSSL 3.6.0
#
# OpenSSL is the industry-standard cryptographic library

include(FetchContent)
include(ExternalProject)

message(STATUS "Fetching OpenSSL 3.6.0...")

# Fetch OpenSSL source
FetchContent_Declare(
    openssl_src
    GIT_REPOSITORY https://github.com/openssl/openssl.git
    GIT_TAG        openssl-3.6.0  # Version 3.6.0 as confirmed in release
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(openssl_src)

set(OPENSSL_SOURCE_DIR ${openssl_src_SOURCE_DIR})
set(OPENSSL_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build)
set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-install)

# Limit build parallelism on CI to reduce memory use
set(OPENSSL_JOBS ${CMAKE_BUILD_PARALLEL_LEVEL})
if(DEFINED ENV{CI})
    set(OPENSSL_JOBS 2)
endif()

# Select platform-specific build/install commands (avoid generator expressions here)
if(WIN32)
    set(OPENSSL_BUILD_CMD nmake)
    set(OPENSSL_INSTALL_CMD nmake install_sw)
else()
    set(OPENSSL_BUILD_CMD make -j${OPENSSL_JOBS})
    set(OPENSSL_INSTALL_CMD make install_sw)
endif()

# Determine the target platform for OpenSSL's Configure script
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(OPENSSL_TARGET "darwin64-arm64-cc")
    else()
        set(OPENSSL_TARGET "darwin64-x86_64-cc")
    endif()
elseif(WIN32)
    # Windows platform configuration for OpenSSL
    if(MSVC)
        # Visual Studio compiler
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(OPENSSL_TARGET "VC-WIN64A")  # 64-bit Windows
        else()
            set(OPENSSL_TARGET "VC-WIN32")   # 32-bit Windows
        endif()
    elseif(MINGW)
        # MinGW compiler
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(OPENSSL_TARGET "mingw64")    # 64-bit MinGW
        else()
            set(OPENSSL_TARGET "mingw")      # 32-bit MinGW
        endif()
    else()
        # Default to Visual Studio 64-bit
        set(OPENSSL_TARGET "VC-WIN64A")
    endif()
elseif(UNIX)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
        set(OPENSSL_TARGET "linux-x86_64")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(OPENSSL_TARGET "linux-aarch64")
    else()
        set(OPENSSL_TARGET "linux-generic64")
    endif()
else()
    message(FATAL_ERROR "Unsupported platform for OpenSSL build")
endif()

# Get compiler flags from our project - convert list to space-separated string
string(REPLACE ";" " " OPENSSL_CFLAGS "${CRYPTO_BENCH_C_FLAGS}")
string(REPLACE ";" " " OPENSSL_CXXFLAGS "${CRYPTO_BENCH_CXX_FLAGS}")

# Find Perl (required for OpenSSL's build system)
find_package(Perl REQUIRED)

# Configure OpenSSL build options
# We want static libraries only, but keep all crypto functionality we need
set(OPENSSL_CONFIG_OPTIONS
    --prefix=${OPENSSL_INSTALL_DIR}
    --openssldir=${OPENSSL_INSTALL_DIR}/ssl
    no-shared                    # Static libraries only
    no-apps                      # Don't build openssl command line tool
    no-docs                      # Don't build documentation
    no-tests                     # Don't build tests
    no-fuzz-libfuzzer           # Don't build fuzzing tests
    no-fuzz-afl                 # Don't build AFL fuzzing
    
    # Disable SSL/TLS (we only want crypto)
    no-ssl3                     # Disable SSL 3.0
    no-ssl3-method             # Disable SSL 3.0 methods
    no-tls1                    # Don't build TLSv1
    no-tls1_1                  # Don't build TLSv1.1
    no-tls1_2                  # Don't build TLSv1.2
    no-tls1_3                  # Don't build TLSv1.3
    no-ssl                     # Don't build SSL/TLS (we only want crypto)
    no-dtls                    # Don't build DTLS
    no-dtls1                   # Don't build DTLSv1
    no-dtls1_2                 # Don't build DTLSv1.2
    
    # Disable unused/legacy ciphers but keep what we need
    no-weak-ssl-ciphers        # Disable weak ciphers
    no-idea                    # Don't build IDEA cipher
    no-mdc2                    # Don't build MDC2
    no-rc5                     # Don't build RC5
    no-rc2                     # Don't build RC2
    no-bf                      # Don't build Blowfish
    no-cast                    # Don't build CAST
    no-des                     # Don't build DES (deprecated)
    
    # Disable protocols we don't need
    no-srp                     # Don't build SRP
    no-psk                     # Don't build PSK
    no-ts                      # Don't build timestamping
    no-cms                     # Don't build CMS
    no-ct                      # Don't build certificate transparency
    
    # Disable compression and dynamic features
    no-zlib                    # Don't use zlib compression
    no-zlib-dynamic            # Don't use dynamic zlib
    no-comp                    # Disable compression
    no-dgram                   # Don't build datagram support
    no-module                  # Don't build loadable modules
    no-dynamic-engine          # Don't build dynamic engines
    no-engine                  # Don't build engines
    no-async                   # Don't build async support
    
    # Keep essential crypto features enabled:
    # - Hash functions: SHA-256, SHA-512, SHA3-256, BLAKE2b (enabled by default)
    # - AES: AES-128-GCM, AES-256-GCM, AES-256-CBC (enabled by default)
    # - ChaCha20-Poly1305 (enabled by default in OpenSSL 3.x)
    # - RSA: RSA-2048, RSA-4096 (enabled by default)
    # - ECDSA: ECDSA-P256 (enabled by default)
    # - Ed25519 (enabled by default in OpenSSL 3.x)
    # - ECDH: ECDH-P256 (enabled by default)
    # - X25519 (enabled by default in OpenSSL 3.x)
    # - HMAC-SHA256 (enabled by default)
    # - Poly1305 (enabled by default in OpenSSL 3.x)
)

# On Windows CI, avoid NASM requirement by disabling assembly
if(WIN32)
    list(APPEND OPENSSL_CONFIG_OPTIONS no-asm)
endif()

# Use ExternalProject_Add to build OpenSSL
ExternalProject_Add(
    openssl_external
    SOURCE_DIR ${OPENSSL_SOURCE_DIR}
    BINARY_DIR ${OPENSSL_BUILD_DIR}
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env
        CC=${CMAKE_C_COMPILER}
        CXX=${CMAKE_CXX_COMPILER}
        CFLAGS=${OPENSSL_CFLAGS}
        CXXFLAGS=${OPENSSL_CXXFLAGS}
        ${PERL_EXECUTABLE} ${OPENSSL_SOURCE_DIR}/Configure
        ${OPENSSL_TARGET}
        ${OPENSSL_CONFIG_OPTIONS}
    BUILD_COMMAND
        ${CMAKE_COMMAND} -E echo "Building OpenSSL 3.6.0..." &&
        ${OPENSSL_BUILD_CMD}
    INSTALL_COMMAND
        ${OPENSSL_INSTALL_CMD}  # install_sw = install software only (no docs)
    BUILD_IN_SOURCE 0
    BUILD_ALWAYS 0
    BUILD_BYPRODUCTS
        ${OPENSSL_BUILD_DIR}/libcrypto.a
        ${OPENSSL_BUILD_DIR}/libssl.a
        ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a
        ${OPENSSL_INSTALL_DIR}/lib/libssl.a
        ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib
        ${OPENSSL_INSTALL_DIR}/lib/libssl.lib
    STEP_TARGETS configure build install
)

# Create a function to set up OpenSSL imported targets after the build
function(setup_openssl_targets)
    # Ensure the install directory exists
    file(MAKE_DIRECTORY "${OPENSSL_INSTALL_DIR}/include")
    
    # Create imported targets for OpenSSL libraries
    # Prefer linking against build tree outputs to avoid lib vs lib64 install differences
    add_library(OpenSSL::Crypto STATIC IMPORTED GLOBAL)
    add_library(OpenSSL::SSL STATIC IMPORTED GLOBAL)

    if(WIN32)
        set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
        set(OPENSSL_SSL_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libssl.lib)
        set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
    else()
        set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_BUILD_DIR}/libcrypto.a)
        set(OPENSSL_SSL_LIBRARY ${OPENSSL_BUILD_DIR}/libssl.a)
        # Use installed headers to ensure generated configuration.h is available
        set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
    endif()

    # Ensure no stale include dirs remain on reconfigure
    set_property(TARGET OpenSSL::Crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES "")
    set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
    )

    set_property(TARGET OpenSSL::SSL PROPERTY INTERFACE_INCLUDE_DIRECTORIES "")
    set_target_properties(OpenSSL::SSL PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
    )

    # Make sure the libraries are built before they're used
    add_dependencies(OpenSSL::Crypto openssl_external)
    add_dependencies(OpenSSL::SSL openssl_external)
endfunction()

# Set up the targets immediately
setup_openssl_targets()

# On some platforms, OpenSSL may need additional system libraries
if(WIN32)
    # Windows needs ws2_32, crypt32, and advapi32
    set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
        INTERFACE_LINK_LIBRARIES ws2_32 crypt32 advapi32)
elseif(UNIX AND NOT APPLE)
    # Linux may need libdl and libpthread
    find_library(DL_LIBRARY dl)
    if(DL_LIBRARY)
        set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES ${DL_LIBRARY})
    endif()

    find_library(PTHREAD_LIBRARY pthread)
    if(PTHREAD_LIBRARY)
        set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES ${PTHREAD_LIBRARY})
    endif()
elseif(APPLE)
    # macOS may need CoreFoundation and Security frameworks
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(SECURITY_LIBRARY Security)
    if(COREFOUNDATION_LIBRARY)
        set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES ${COREFOUNDATION_LIBRARY})
    endif()
    if(SECURITY_LIBRARY)
        set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES ${SECURITY_LIBRARY})
    endif()
endif()

message(STATUS "OpenSSL 3.6.0 configured successfully")