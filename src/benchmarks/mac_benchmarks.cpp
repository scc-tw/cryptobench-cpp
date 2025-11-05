/**
 * mac_benchmarks.cpp - Benchmarks for message authentication codes
 *
 * Tests HMAC-SHA256 and Poly1305 across all libraries
 */

#include <benchmark/benchmark.h>
#include <vector>
#include <memory>
#include <random>
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

// Generic MAC computation benchmark template
template<typename MACFactory>
void BM_MACCompute(benchmark::State& state, MACFactory factory) {
    const size_t message_size = state.range(0);
    
    // Create the MAC adapter
    auto mac = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> message(message_size);
    std::vector<uint8_t> key(mac->key_size());
    std::vector<uint8_t> mac_output(mac->mac_size());
    
    // Initialize with pseudo-random data
    std::mt19937 rng(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (size_t i = 0; i < message_size; ++i) {
        message[i] = static_cast<uint8_t>(i & 0xFF);
    }
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = dist(rng);
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            mac->compute(message.data(), message.size(),
                        key.data(), key.size(),
                        mac_output.data(), mac_output.size());
            benchmark::DoNotOptimize(mac_output.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("MAC computation failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * message_size);
}

// Generic MAC verification benchmark template
template<typename MACFactory>
void BM_MACVerify(benchmark::State& state, MACFactory factory) {
    const size_t message_size = state.range(0);
    
    // Create the MAC adapter
    auto mac = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> message(message_size);
    std::vector<uint8_t> key(mac->key_size());
    std::vector<uint8_t> mac_output(mac->mac_size());
    
    // Initialize with pseudo-random data
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (size_t i = 0; i < message_size; ++i) {
        message[i] = static_cast<uint8_t>(i & 0xFF);
    }
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = dist(rng);
    }
    
    // Compute MAC once for verification
    try {
        mac->compute(message.data(), message.size(),
                    key.data(), key.size(),
                    mac_output.data(), mac_output.size());
    } catch (const std::exception&) {
        state.SkipWithError("Initial MAC computation failed");
        return;
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            bool result = mac->verify(message.data(), message.size(),
                                     key.data(), key.size(),
                                     mac_output.data(), mac_output.size());
            benchmark::DoNotOptimize(result);
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("MAC verification failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * message_size);
}

// Data sizes to test (64B, 256B, 1KB, 4KB, 16KB)
const std::vector<int64_t> kDataSizes = {64, 256, 1024, 4096, 16384};

// Register benchmarks for each library and algorithm

#ifdef ENABLE_CRYPTOPP

// Crypto++ HMAC-SHA256 Compute
static void BM_Cryptopp_HMACSHA256_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::cryptopp::create_hmac_sha256(); });
}
BENCHMARK(BM_Cryptopp_HMACSHA256_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ HMAC-SHA256 Verify
static void BM_Cryptopp_HMACSHA256_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::cryptopp::create_hmac_sha256(); });
}
BENCHMARK(BM_Cryptopp_HMACSHA256_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ Poly1305 Compute
static void BM_Cryptopp_Poly1305_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::cryptopp::create_poly1305(); });
}
BENCHMARK(BM_Cryptopp_Poly1305_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ Poly1305 Verify
static void BM_Cryptopp_Poly1305_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::cryptopp::create_poly1305(); });
}
BENCHMARK(BM_Cryptopp_Poly1305_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_CRYPTOPP

#ifdef ENABLE_OPENSSL

// OpenSSL HMAC-SHA256 Compute
static void BM_OpenSSL_HMACSHA256_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::openssl::create_hmac_sha256(); });
}
BENCHMARK(BM_OpenSSL_HMACSHA256_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL HMAC-SHA256 Verify
static void BM_OpenSSL_HMACSHA256_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::openssl::create_hmac_sha256(); });
}
BENCHMARK(BM_OpenSSL_HMACSHA256_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL Poly1305 Compute
static void BM_OpenSSL_Poly1305_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::openssl::create_poly1305(); });
}
BENCHMARK(BM_OpenSSL_Poly1305_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL Poly1305 Verify
static void BM_OpenSSL_Poly1305_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::openssl::create_poly1305(); });
}
BENCHMARK(BM_OpenSSL_Poly1305_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_OPENSSL

#ifdef ENABLE_BOTAN

// Botan HMAC-SHA256 Compute
static void BM_Botan_HMACSHA256_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::botan::create_hmac_sha256(); });
}
BENCHMARK(BM_Botan_HMACSHA256_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan HMAC-SHA256 Verify
static void BM_Botan_HMACSHA256_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::botan::create_hmac_sha256(); });
}
BENCHMARK(BM_Botan_HMACSHA256_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan Poly1305 Compute
static void BM_Botan_Poly1305_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::botan::create_poly1305(); });
}
BENCHMARK(BM_Botan_Poly1305_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan Poly1305 Verify
static void BM_Botan_Poly1305_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::botan::create_poly1305(); });
}
BENCHMARK(BM_Botan_Poly1305_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_BOTAN

#ifdef ENABLE_LIBSODIUM

// libsodium HMAC-SHA256 Compute
static void BM_Libsodium_HMACSHA256_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::libsodium::create_hmac_sha256(); });
}
BENCHMARK(BM_Libsodium_HMACSHA256_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium HMAC-SHA256 Verify
static void BM_Libsodium_HMACSHA256_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::libsodium::create_hmac_sha256(); });
}
BENCHMARK(BM_Libsodium_HMACSHA256_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium HMAC-SHA512 Compute (bonus)
static void BM_Libsodium_HMACSHA512_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::libsodium::create_hmac_sha512(); });
}
BENCHMARK(BM_Libsodium_HMACSHA512_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium HMAC-SHA512 Verify (bonus)
static void BM_Libsodium_HMACSHA512_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::libsodium::create_hmac_sha512(); });
}
BENCHMARK(BM_Libsodium_HMACSHA512_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium Poly1305 Compute
static void BM_Libsodium_Poly1305_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::libsodium::create_poly1305(); });
}
BENCHMARK(BM_Libsodium_Poly1305_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium Poly1305 Verify
static void BM_Libsodium_Poly1305_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::libsodium::create_poly1305(); });
}
BENCHMARK(BM_Libsodium_Poly1305_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_LIBSODIUM

#ifdef ENABLE_MBEDTLS

// mbedTLS HMAC-SHA256 Compute
static void BM_MbedTLS_HMACSHA256_Compute(benchmark::State& state) {
    BM_MACCompute(state, []() { return crypto_bench::mbedtls::create_hmac_sha256(); });
}
BENCHMARK(BM_MbedTLS_HMACSHA256_Compute)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS HMAC-SHA256 Verify
static void BM_MbedTLS_HMACSHA256_Verify(benchmark::State& state) {
    BM_MACVerify(state, []() { return crypto_bench::mbedtls::create_hmac_sha256(); });
}
BENCHMARK(BM_MbedTLS_HMACSHA256_Verify)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Note: mbedTLS doesn't have standalone Poly1305 in version 4.0.0

#endif // ENABLE_MBEDTLS

} // anonymous namespace
