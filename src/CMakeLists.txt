# src/CMakeLists.txt - Build configuration for crypto-bench executable

# Collect source files
set(CRYPTO_BENCH_SOURCES
    main.cpp
)

# Add common headers
set(CRYPTO_BENCH_HEADERS
    # Will be populated as we add headers
)

# Collect adapter sources based on enabled libraries
if(BUILD_CRYPTOPP)
    list(APPEND CRYPTO_BENCH_SOURCES
        adapters/cryptopp_adapter.cpp
    )
endif()

if(BUILD_OPENSSL)
    list(APPEND CRYPTO_BENCH_SOURCES
        adapters/openssl_adapter.cpp
    )
endif()

if(BUILD_BOTAN)
    list(APPEND CRYPTO_BENCH_SOURCES
        adapters/botan_adapter.cpp
    )
endif()

if(BUILD_LIBSODIUM)
    list(APPEND CRYPTO_BENCH_SOURCES
        adapters/libsodium_adapter.cpp
    )
endif()

if(BUILD_MBEDTLS)
    list(APPEND CRYPTO_BENCH_SOURCES
        adapters/mbedtls_adapter.cpp
    )
endif()

# Collect benchmark sources
list(APPEND CRYPTO_BENCH_SOURCES
    benchmarks/hash_benchmarks.cpp
    benchmarks/symmetric_benchmarks.cpp
    benchmarks/asymmetric_benchmarks.cpp
    benchmarks/kex_benchmarks.cpp
    benchmarks/mac_benchmarks.cpp
)

# Create the executable
add_executable(crypto-bench ${CRYPTO_BENCH_SOURCES} ${CRYPTO_BENCH_HEADERS})

# Set C++ standard
# Using C++20 for modern features and better performance
target_compile_features(crypto-bench PRIVATE cxx_std_20)

# Apply optimization flags
target_compile_options(crypto-bench PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})

# Include directories
target_include_directories(crypto-bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/adapters
    ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks
)


# Apply preprocessor defines
target_compile_definitions(crypto-bench PRIVATE ${CRYPTO_BENCH_DEFINES})

# Link against Google Benchmark
target_link_libraries(crypto-bench PRIVATE benchmark::benchmark)

# Link against cryptographic libraries
if(BUILD_CRYPTOPP)
    target_link_libraries(crypto-bench PRIVATE cryptopp::cryptopp)
endif()

if(BUILD_OPENSSL)
    target_link_libraries(crypto-bench PRIVATE OpenSSL::Crypto)
endif()

if(BUILD_BOTAN)
    target_link_libraries(crypto-bench PRIVATE botan::botan)
endif()

if(BUILD_LIBSODIUM)
    target_link_libraries(crypto-bench PRIVATE libsodium::sodium)
endif()

if(BUILD_MBEDTLS)
    # mbedTLS 4.0.0 renamed mbedcrypto to tfpsacrypto, but we use the compatibility alias
    target_link_libraries(crypto-bench PRIVATE MbedTLS::mbedcrypto)
endif()

# Platform-specific linking
if(UNIX AND NOT APPLE)
    # Linux may need pthread and rt
    target_link_libraries(crypto-bench PRIVATE pthread rt)
elseif(APPLE)
    # macOS specific linking if needed
endif()

# Set output directory
set_target_properties(crypto-bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Install target (optional)
install(TARGETS crypto-bench
    RUNTIME DESTINATION bin
)