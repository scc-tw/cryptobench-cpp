/**
 * kex_benchmarks.cpp - Benchmarks for key exchange algorithms
 *
 * Tests ECDH-P256 and X25519 across all libraries
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

// Generic key exchange benchmark template for keypair generation
template<typename KexFactory>
void BM_KexKeypairGeneration(benchmark::State& state, KexFactory factory) {
    // Create the key exchange adapter
    auto kex = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> public_key(kex->public_key_size());
    std::vector<uint8_t> private_key(kex->private_key_size());
    size_t public_key_len = public_key.size();
    size_t private_key_len = private_key.size();
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            public_key_len = public_key.size();
            private_key_len = private_key.size();
            kex->generate_keypair(public_key.data(), &public_key_len,
                                 private_key.data(), &private_key_len);
            benchmark::DoNotOptimize(public_key.data());
            benchmark::DoNotOptimize(private_key.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("Keypair generation failed");
            break;
        }
    }
    
    // Set operations per second (no meaningful bytes processed for key generation)
    state.SetItemsProcessed(state.iterations());
}

// Generic key exchange benchmark template for shared secret computation
template<typename KexFactory>
void BM_KexSharedSecret(benchmark::State& state, KexFactory factory) {
    // Create the key exchange adapter
    auto kex = factory();
    
    // Pre-allocate buffers
    std::vector<uint8_t> our_public_key(kex->public_key_size());
    std::vector<uint8_t> our_private_key(kex->private_key_size());
    std::vector<uint8_t> peer_public_key(kex->public_key_size());
    std::vector<uint8_t> peer_private_key(kex->private_key_size());
    std::vector<uint8_t> shared_secret(kex->shared_secret_size());
    
    size_t our_public_key_len = our_public_key.size();
    size_t our_private_key_len = our_private_key.size();
    size_t peer_public_key_len = peer_public_key.size();
    size_t peer_private_key_len = peer_private_key.size();
    size_t shared_secret_len = shared_secret.size();
    
    // Generate keypairs for testing
    try {
        kex->generate_keypair(our_public_key.data(), &our_public_key_len,
                             our_private_key.data(), &our_private_key_len);
        kex->generate_keypair(peer_public_key.data(), &peer_public_key_len,
                             peer_private_key.data(), &peer_private_key_len);
    } catch (const std::exception&) {
        state.SkipWithError("Initial keypair generation failed");
        return;
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            shared_secret_len = shared_secret.size();
            kex->compute_shared_secret(our_private_key.data(), our_private_key_len,
                                      peer_public_key.data(), peer_public_key_len,
                                      shared_secret.data(), &shared_secret_len);
            benchmark::DoNotOptimize(shared_secret.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("Shared secret computation failed");
            break;
        }
    }
    
    // Set operations per second
    state.SetItemsProcessed(state.iterations());
}

// Register benchmarks for each library and algorithm

#ifdef ENABLE_CRYPTOPP

// Crypto++ ECDH-P256 Keypair Generation
static void BM_Cryptopp_ECDHP256_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::cryptopp::create_ecdh_p256(); });
}
BENCHMARK(BM_Cryptopp_ECDHP256_Keygen)->Unit(benchmark::kMicrosecond);

// Crypto++ ECDH-P256 Shared Secret
static void BM_Cryptopp_ECDHP256_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::cryptopp::create_ecdh_p256(); });
}
BENCHMARK(BM_Cryptopp_ECDHP256_SharedSecret)->Unit(benchmark::kMicrosecond);

// Crypto++ X25519 Keypair Generation
static void BM_Cryptopp_X25519_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::cryptopp::create_x25519(); });
}
BENCHMARK(BM_Cryptopp_X25519_Keygen)->Unit(benchmark::kMicrosecond);

// Crypto++ X25519 Shared Secret
static void BM_Cryptopp_X25519_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::cryptopp::create_x25519(); });
}
BENCHMARK(BM_Cryptopp_X25519_SharedSecret)->Unit(benchmark::kMicrosecond);

#endif // ENABLE_CRYPTOPP

#ifdef ENABLE_OPENSSL

// OpenSSL ECDH-P256 Keypair Generation
static void BM_OpenSSL_ECDHP256_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::openssl::create_ecdh_p256(); });
}
BENCHMARK(BM_OpenSSL_ECDHP256_Keygen)->Unit(benchmark::kMicrosecond);

// OpenSSL ECDH-P256 Shared Secret
static void BM_OpenSSL_ECDHP256_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::openssl::create_ecdh_p256(); });
}
BENCHMARK(BM_OpenSSL_ECDHP256_SharedSecret)->Unit(benchmark::kMicrosecond);

// OpenSSL X25519 Keypair Generation
static void BM_OpenSSL_X25519_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::openssl::create_x25519(); });
}
BENCHMARK(BM_OpenSSL_X25519_Keygen)->Unit(benchmark::kMicrosecond);

// OpenSSL X25519 Shared Secret
static void BM_OpenSSL_X25519_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::openssl::create_x25519(); });
}
BENCHMARK(BM_OpenSSL_X25519_SharedSecret)->Unit(benchmark::kMicrosecond);

#endif // ENABLE_OPENSSL

#ifdef ENABLE_BOTAN

// Botan ECDH-P256 Keypair Generation
static void BM_Botan_ECDHP256_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::botan::create_ecdh_p256(); });
}
BENCHMARK(BM_Botan_ECDHP256_Keygen)->Unit(benchmark::kMicrosecond);

// Botan ECDH-P256 Shared Secret
static void BM_Botan_ECDHP256_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::botan::create_ecdh_p256(); });
}
BENCHMARK(BM_Botan_ECDHP256_SharedSecret)->Unit(benchmark::kMicrosecond);

// Botan X25519 Keypair Generation
static void BM_Botan_X25519_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::botan::create_x25519(); });
}
BENCHMARK(BM_Botan_X25519_Keygen)->Unit(benchmark::kMicrosecond);

// Botan X25519 Shared Secret
static void BM_Botan_X25519_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::botan::create_x25519(); });
}
BENCHMARK(BM_Botan_X25519_SharedSecret)->Unit(benchmark::kMicrosecond);

#endif // ENABLE_BOTAN

#ifdef ENABLE_LIBSODIUM

// libsodium X25519 Keypair Generation
static void BM_Libsodium_X25519_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::libsodium::create_x25519(); });
}
BENCHMARK(BM_Libsodium_X25519_Keygen)->Unit(benchmark::kMicrosecond);

// libsodium X25519 Shared Secret
static void BM_Libsodium_X25519_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::libsodium::create_x25519(); });
}
BENCHMARK(BM_Libsodium_X25519_SharedSecret)->Unit(benchmark::kMicrosecond);

// Note: libsodium doesn't have ECDH-P256

#endif // ENABLE_LIBSODIUM

#ifdef ENABLE_MBEDTLS

// mbedTLS ECDH-P256 Keypair Generation
static void BM_MbedTLS_ECDHP256_Keygen(benchmark::State& state) {
    BM_KexKeypairGeneration(state, []() { return crypto_bench::mbedtls::create_ecdh_p256(); });
}
BENCHMARK(BM_MbedTLS_ECDHP256_Keygen)->Unit(benchmark::kMicrosecond);

// mbedTLS ECDH-P256 Shared Secret
static void BM_MbedTLS_ECDHP256_SharedSecret(benchmark::State& state) {
    BM_KexSharedSecret(state, []() { return crypto_bench::mbedtls::create_ecdh_p256(); });
}
BENCHMARK(BM_MbedTLS_ECDHP256_SharedSecret)->Unit(benchmark::kMicrosecond);

// Note: mbedTLS doesn't have X25519 in version 4.0.0

#endif // ENABLE_MBEDTLS

} // anonymous namespace
