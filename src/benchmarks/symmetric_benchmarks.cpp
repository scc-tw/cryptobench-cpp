/**
 * symmetric_benchmarks.cpp - Benchmarks for symmetric encryption
 *
 * Tests AES-128-GCM, AES-256-GCM, AES-256-CBC, and ChaCha20-Poly1305 across all libraries
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

// Generic symmetric encryption benchmark template
template<typename SymmetricFactory>
void BM_SymmetricEncrypt(benchmark::State& state, SymmetricFactory factory) {
    const size_t data_size = state.range(0);
    
    // Create the symmetric adapter
    auto cipher = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> plaintext(data_size);
    std::vector<uint8_t> ciphertext(data_size + 16); // allow up to one full block of padding
    std::vector<uint8_t> key(cipher->key_size());
    std::vector<uint8_t> iv(cipher->iv_size());
    std::vector<uint8_t> tag(cipher->tag_size());
    std::vector<uint8_t> aad(16); // Small AAD for AEAD modes
    
    // Initialize with pseudo-random data
    std::mt19937 rng(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (size_t i = 0; i < data_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = dist(rng);
    }
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = dist(rng);
    }
    for (size_t i = 0; i < aad.size(); ++i) {
        aad[i] = dist(rng);
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            cipher->encrypt(
                plaintext.data(), plaintext.size(),
                key.data(), key.size(),
                iv.data(), iv.size(),
                aad.data(), aad.size(),
                ciphertext.data(),
                tag.data(), tag.size()
            );
            benchmark::DoNotOptimize(ciphertext.data());
            benchmark::DoNotOptimize(tag.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            // Skip if not supported
            state.SkipWithError("Encryption failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * data_size);
}

// Generic CBC encryption benchmark template
template<typename SymmetricFactory>
void BM_SymmetricEncryptCBC(benchmark::State& state, SymmetricFactory factory) {
    const size_t data_size = state.range(0);
    
    // Create the symmetric adapter
    auto cipher = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> plaintext(data_size);
    std::vector<uint8_t> ciphertext(data_size);
    std::vector<uint8_t> key(cipher->key_size());
    std::vector<uint8_t> iv(cipher->iv_size());
    
    // Initialize with pseudo-random data
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    for (size_t i = 0; i < data_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = dist(rng);
    }
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = dist(rng);
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            cipher->encrypt_cbc(
                plaintext.data(), plaintext.size(),
                key.data(), key.size(),
                iv.data(), iv.size(),
                ciphertext.data()
            );
            benchmark::DoNotOptimize(ciphertext.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            // Skip if not supported
            state.SkipWithError("CBC encryption failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * data_size);
}

// Data sizes to test (64B, 256B, 1KB, 4KB, 16KB)
const std::vector<int64_t> kDataSizes = {64, 256, 1024, 4096, 16384};

// Register benchmarks for each library and algorithm

#ifdef ENABLE_CRYPTOPP

// Crypto++ AES-128-GCM
static void BM_Cryptopp_AES128GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::cryptopp::create_aes_128_gcm(); });
}
BENCHMARK(BM_Cryptopp_AES128GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ AES-256-GCM
static void BM_Cryptopp_AES256GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::cryptopp::create_aes_256_gcm(); });
}
BENCHMARK(BM_Cryptopp_AES256GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ AES-256-CBC
static void BM_Cryptopp_AES256CBC(benchmark::State& state) {
    BM_SymmetricEncryptCBC(state, []() { return crypto_bench::cryptopp::create_aes_256_cbc(); });
}
BENCHMARK(BM_Cryptopp_AES256CBC)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ ChaCha20-Poly1305
static void BM_Cryptopp_ChaCha20Poly1305(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::cryptopp::create_chacha20_poly1305(); });
}
BENCHMARK(BM_Cryptopp_ChaCha20Poly1305)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_CRYPTOPP

#ifdef ENABLE_OPENSSL

// OpenSSL AES-128-GCM
static void BM_OpenSSL_AES128GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::openssl::create_aes_128_gcm(); });
}
BENCHMARK(BM_OpenSSL_AES128GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL AES-256-GCM
static void BM_OpenSSL_AES256GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::openssl::create_aes_256_gcm(); });
}
BENCHMARK(BM_OpenSSL_AES256GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL AES-256-CBC
static void BM_OpenSSL_AES256CBC(benchmark::State& state) {
    BM_SymmetricEncryptCBC(state, []() { return crypto_bench::openssl::create_aes_256_cbc(); });
}
BENCHMARK(BM_OpenSSL_AES256CBC)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL ChaCha20-Poly1305
static void BM_OpenSSL_ChaCha20Poly1305(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::openssl::create_chacha20_poly1305(); });
}
BENCHMARK(BM_OpenSSL_ChaCha20Poly1305)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_OPENSSL

#ifdef ENABLE_BOTAN

// Botan AES-128-GCM
static void BM_Botan_AES128GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::botan::create_aes_128_gcm(); });
}
BENCHMARK(BM_Botan_AES128GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan AES-256-GCM
static void BM_Botan_AES256GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::botan::create_aes_256_gcm(); });
}
BENCHMARK(BM_Botan_AES256GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan AES-256-CBC
static void BM_Botan_AES256CBC(benchmark::State& state) {
    BM_SymmetricEncryptCBC(state, []() { return crypto_bench::botan::create_aes_256_cbc(); });
}
BENCHMARK(BM_Botan_AES256CBC)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Botan ChaCha20-Poly1305
static void BM_Botan_ChaCha20Poly1305(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::botan::create_chacha20_poly1305(); });
}
BENCHMARK(BM_Botan_ChaCha20Poly1305)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_BOTAN

#ifdef ENABLE_LIBSODIUM

// libsodium AES-256-GCM (if available)
static void BM_Libsodium_AES256GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::libsodium::create_aes_256_gcm(); });
}
BENCHMARK(BM_Libsodium_AES256GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// libsodium ChaCha20-Poly1305
static void BM_Libsodium_ChaCha20Poly1305(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::libsodium::create_chacha20_poly1305(); });
}
BENCHMARK(BM_Libsodium_ChaCha20Poly1305)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// Note: libsodium doesn't have AES-128-GCM or AES-256-CBC in high-level API

#endif // ENABLE_LIBSODIUM

#ifdef ENABLE_MBEDTLS

// mbedTLS AES-128-GCM
static void BM_MbedTLS_AES128GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::mbedtls::create_aes_128_gcm(); });
}
BENCHMARK(BM_MbedTLS_AES128GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS AES-256-GCM
static void BM_MbedTLS_AES256GCM(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::mbedtls::create_aes_256_gcm(); });
}
BENCHMARK(BM_MbedTLS_AES256GCM)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS AES-256-CBC
static void BM_MbedTLS_AES256CBC(benchmark::State& state) {
    BM_SymmetricEncryptCBC(state, []() { return crypto_bench::mbedtls::create_aes_256_cbc(); });
}
BENCHMARK(BM_MbedTLS_AES256CBC)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS ChaCha20-Poly1305
static void BM_MbedTLS_ChaCha20Poly1305(benchmark::State& state) {
    BM_SymmetricEncrypt(state, []() { return crypto_bench::mbedtls::create_chacha20_poly1305(); });
}
BENCHMARK(BM_MbedTLS_ChaCha20Poly1305)->Arg(64)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_MBEDTLS

} // anonymous namespace
