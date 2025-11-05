/**
 * hash_benchmarks.cpp - Benchmarks for hash functions
 *
 * Tests SHA-256, SHA-512, SHA3-256, and BLAKE2b across all libraries
 */

#include <benchmark/benchmark.h>
#include <vector>
#include <memory>
#include "common/crypto_adapter.h"

#ifdef ENABLE_CRYPTOPP
#include "adapters/cryptopp_adapter.h"
#endif

#ifdef ENABLE_OPENSSL
#include "adapters/openssl_adapter.h"
#endif

#ifdef ENABLE_BOTAN
#include "adapters/botan_adapter.h"
#endif

#ifdef ENABLE_LIBSODIUM
#include "adapters/libsodium_adapter.h"
#endif

#ifdef ENABLE_MBEDTLS
#include "adapters/mbedtls_adapter.h"
#endif

namespace {

// Generic hash benchmark template
template<typename HashFactory>
void BM_Hash(benchmark::State& state, HashFactory factory) {
    const size_t data_size = state.range(0);

    // Pre-allocate buffers
    std::vector<uint8_t> data(data_size);

    // Initialize with pseudo-random data
    for (size_t i = 0; i < data_size; ++i) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Create the hash adapter
    auto hasher = factory();
    std::vector<uint8_t> output(hasher->output_size());

    // Benchmark loop
    for (auto _ : state) {
        hasher->hash(data.data(), data.size(), output.data());
        benchmark::DoNotOptimize(output.data());
        benchmark::ClobberMemory();
    }

    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * data_size);
}

// Data sizes to test (64B, 256B, 1KB, 4KB, 16KB)
const std::vector<int64_t> kDataSizes = {64, 256, 1024, 4096, 16384};

// Register benchmarks for each library and algorithm

#ifdef ENABLE_CRYPTOPP

// Crypto++ SHA-256
static void BM_Cryptopp_SHA256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::cryptopp::create_sha256(); });
}
BENCHMARK(BM_Cryptopp_SHA256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ SHA-512
static void BM_Cryptopp_SHA512(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::cryptopp::create_sha512(); });
}
BENCHMARK(BM_Cryptopp_SHA512)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ SHA3-256
static void BM_Cryptopp_SHA3_256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::cryptopp::create_sha3_256(); });
}
BENCHMARK(BM_Cryptopp_SHA3_256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ BLAKE2b
static void BM_Cryptopp_BLAKE2b(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::cryptopp::create_blake2b(); });
}
BENCHMARK(BM_Cryptopp_BLAKE2b)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_CRYPTOPP

#ifdef ENABLE_OPENSSL

// OpenSSL SHA-256
static void BM_OpenSSL_SHA256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::openssl::create_sha256(); });
}
BENCHMARK(BM_OpenSSL_SHA256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL SHA-512
static void BM_OpenSSL_SHA512(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::openssl::create_sha512(); });
}
BENCHMARK(BM_OpenSSL_SHA512)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL SHA3-256
static void BM_OpenSSL_SHA3_256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::openssl::create_sha3_256(); });
}
BENCHMARK(BM_OpenSSL_SHA3_256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL BLAKE2b
static void BM_OpenSSL_BLAKE2b(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::openssl::create_blake2b(); });
}
BENCHMARK(BM_OpenSSL_BLAKE2b)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_OPENSSL

#ifdef ENABLE_BOTAN

// Botan SHA-256
static void BM_Botan_SHA256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::botan::create_sha256(); });
}
BENCHMARK(BM_Botan_SHA256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan SHA-512
static void BM_Botan_SHA512(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::botan::create_sha512(); });
}
BENCHMARK(BM_Botan_SHA512)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan SHA3-256
static void BM_Botan_SHA3_256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::botan::create_sha3_256(); });
}
BENCHMARK(BM_Botan_SHA3_256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan BLAKE2b
static void BM_Botan_BLAKE2b(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::botan::create_blake2b(); });
}
BENCHMARK(BM_Botan_BLAKE2b)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_BOTAN

#ifdef ENABLE_LIBSODIUM

// libsodium SHA-256
static void BM_Libsodium_SHA256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::libsodium::create_sha256(); });
}
BENCHMARK(BM_Libsodium_SHA256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium SHA-512
static void BM_Libsodium_SHA512(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::libsodium::create_sha512(); });
}
BENCHMARK(BM_Libsodium_SHA512)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Note: libsodium doesn't have SHA3-256, but has BLAKE2b

// libsodium BLAKE2b
static void BM_Libsodium_BLAKE2b(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::libsodium::create_blake2b(); });
}
BENCHMARK(BM_Libsodium_BLAKE2b)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_LIBSODIUM

#ifdef ENABLE_MBEDTLS

// mbedTLS SHA-256
static void BM_MbedTLS_SHA256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::mbedtls::create_sha256(); });
}
BENCHMARK(BM_MbedTLS_SHA256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS SHA-512
static void BM_MbedTLS_SHA512(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::mbedtls::create_sha512(); });
}
BENCHMARK(BM_MbedTLS_SHA512)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS SHA3-256
static void BM_MbedTLS_SHA3_256(benchmark::State& state) {
    BM_Hash(state, []() { return crypto_bench::mbedtls::create_sha3_256(); });
}
BENCHMARK(BM_MbedTLS_SHA3_256)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Note: mbedTLS doesn't support BLAKE2b natively

#endif // ENABLE_MBEDTLS

} // anonymous namespace