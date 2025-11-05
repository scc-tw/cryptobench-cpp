/**
 * asymmetric_benchmarks.cpp - Benchmarks for asymmetric cryptography
 *
 * Tests RSA-2048, RSA-4096, ECDSA-P256, and Ed25519 across all libraries
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

// Generic asymmetric signature benchmark template for signing
template<typename AsymmetricFactory>
void BM_AsymmetricSign(benchmark::State& state, AsymmetricFactory factory) {
    const size_t message_size = state.range(0);
    
    // Create the asymmetric adapter
    auto signer = factory();
    
    // Generate keypair once
    try {
        signer->generate_keypair();
    } catch (const std::exception&) {
        state.SkipWithError("Key generation failed");
        return;
    }
    
    // Pre-allocate buffers
    std::vector<uint8_t> message(message_size);
    std::vector<uint8_t> signature(signer->signature_size());
    size_t signature_len = signature.size();
    
    // Initialize with pseudo-random data
    for (size_t i = 0; i < message_size; ++i) {
        message[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            signature_len = signature.size();
            signer->sign(message.data(), message.size(), signature.data(), &signature_len);
            benchmark::DoNotOptimize(signature.data());
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("Signing failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * message_size);
}

// Generic asymmetric signature benchmark template for verification
template<typename AsymmetricFactory>
void BM_AsymmetricVerify(benchmark::State& state, AsymmetricFactory factory) {
    const size_t message_size = state.range(0);
    
    // Create the asymmetric adapter
    auto signer = factory();
    
    // Generate keypair once
    try {
        signer->generate_keypair();
    } catch (const std::exception&) {
        state.SkipWithError("Key generation failed");
        return;
    }
    
    // Pre-allocate buffers
    std::vector<uint8_t> message(message_size);
    std::vector<uint8_t> signature(signer->signature_size());
    size_t signature_len = signature.size();
    
    // Initialize with pseudo-random data
    for (size_t i = 0; i < message_size; ++i) {
        message[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Create a signature to verify
    try {
        signer->sign(message.data(), message.size(), signature.data(), &signature_len);
    } catch (const std::exception&) {
        state.SkipWithError("Initial signing failed");
        return;
    }
    
    // Benchmark loop
    for (auto _ : state) {
        try {
            bool result = signer->verify(message.data(), message.size(), signature.data(), signature_len);
            benchmark::DoNotOptimize(result);
            benchmark::ClobberMemory();
        } catch (const std::exception&) {
            state.SkipWithError("Verification failed");
            break;
        }
    }
    
    // Set bytes processed for throughput calculation
    state.SetBytesProcessed(state.iterations() * message_size);
}

// Message sizes to test (32B, 128B, 512B, 1KB, 4KB)
const std::vector<int64_t> kMessageSizes = {32, 128, 512, 1024, 4096};

// Register benchmarks for each library and algorithm

#ifdef ENABLE_CRYPTOPP

// Crypto++ RSA-2048 Sign
static void BM_Cryptopp_RSA2048_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::cryptopp::create_rsa_2048(); });
}
BENCHMARK(BM_Cryptopp_RSA2048_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ RSA-2048 Verify
static void BM_Cryptopp_RSA2048_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::cryptopp::create_rsa_2048(); });
}
BENCHMARK(BM_Cryptopp_RSA2048_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ RSA-4096 Sign
static void BM_Cryptopp_RSA4096_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::cryptopp::create_rsa_4096(); });
}
BENCHMARK(BM_Cryptopp_RSA4096_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ RSA-4096 Verify
static void BM_Cryptopp_RSA4096_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::cryptopp::create_rsa_4096(); });
}
BENCHMARK(BM_Cryptopp_RSA4096_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ ECDSA-P256 Sign
static void BM_Cryptopp_ECDSAP256_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::cryptopp::create_ecdsa_p256(); });
}
BENCHMARK(BM_Cryptopp_ECDSAP256_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ ECDSA-P256 Verify
static void BM_Cryptopp_ECDSAP256_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::cryptopp::create_ecdsa_p256(); });
}
BENCHMARK(BM_Cryptopp_ECDSAP256_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ Ed25519 Sign
static void BM_Cryptopp_Ed25519_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::cryptopp::create_ed25519(); });
}
BENCHMARK(BM_Cryptopp_Ed25519_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Crypto++ Ed25519 Verify
static void BM_Cryptopp_Ed25519_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::cryptopp::create_ed25519(); });
}
BENCHMARK(BM_Cryptopp_Ed25519_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_CRYPTOPP

#ifdef ENABLE_OPENSSL

// OpenSSL RSA-2048 Sign
static void BM_OpenSSL_RSA2048_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::openssl::create_rsa_2048(); });
}
BENCHMARK(BM_OpenSSL_RSA2048_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL RSA-2048 Verify
static void BM_OpenSSL_RSA2048_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::openssl::create_rsa_2048(); });
}
BENCHMARK(BM_OpenSSL_RSA2048_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL RSA-4096 Sign
static void BM_OpenSSL_RSA4096_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::openssl::create_rsa_4096(); });
}
BENCHMARK(BM_OpenSSL_RSA4096_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL RSA-4096 Verify
static void BM_OpenSSL_RSA4096_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::openssl::create_rsa_4096(); });
}
BENCHMARK(BM_OpenSSL_RSA4096_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL ECDSA-P256 Sign
static void BM_OpenSSL_ECDSAP256_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::openssl::create_ecdsa_p256(); });
}
BENCHMARK(BM_OpenSSL_ECDSAP256_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL ECDSA-P256 Verify
static void BM_OpenSSL_ECDSAP256_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::openssl::create_ecdsa_p256(); });
}
BENCHMARK(BM_OpenSSL_ECDSAP256_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL Ed25519 Sign
static void BM_OpenSSL_Ed25519_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::openssl::create_ed25519(); });
}
BENCHMARK(BM_OpenSSL_Ed25519_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// OpenSSL Ed25519 Verify
static void BM_OpenSSL_Ed25519_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::openssl::create_ed25519(); });
}
BENCHMARK(BM_OpenSSL_Ed25519_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_OPENSSL

#ifdef ENABLE_BOTAN

// Botan RSA-2048 Sign
static void BM_Botan_RSA2048_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::botan::create_rsa_2048(); });
}
BENCHMARK(BM_Botan_RSA2048_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan RSA-2048 Verify
static void BM_Botan_RSA2048_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::botan::create_rsa_2048(); });
}
BENCHMARK(BM_Botan_RSA2048_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan RSA-4096 Sign
static void BM_Botan_RSA4096_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::botan::create_rsa_4096(); });
}
BENCHMARK(BM_Botan_RSA4096_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan RSA-4096 Verify
static void BM_Botan_RSA4096_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::botan::create_rsa_4096(); });
}
BENCHMARK(BM_Botan_RSA4096_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan ECDSA-P256 Sign
static void BM_Botan_ECDSAP256_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::botan::create_ecdsa_p256(); });
}
BENCHMARK(BM_Botan_ECDSAP256_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan ECDSA-P256 Verify
static void BM_Botan_ECDSAP256_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::botan::create_ecdsa_p256(); });
}
BENCHMARK(BM_Botan_ECDSAP256_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan Ed25519 Sign
static void BM_Botan_Ed25519_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::botan::create_ed25519(); });
}
BENCHMARK(BM_Botan_Ed25519_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Botan Ed25519 Verify
static void BM_Botan_Ed25519_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::botan::create_ed25519(); });
}
BENCHMARK(BM_Botan_Ed25519_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

#endif // ENABLE_BOTAN

#ifdef ENABLE_LIBSODIUM

// libsodium Ed25519 Sign
static void BM_Libsodium_Ed25519_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::libsodium::create_ed25519(); });
}
BENCHMARK(BM_Libsodium_Ed25519_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// libsodium Ed25519 Verify
static void BM_Libsodium_Ed25519_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::libsodium::create_ed25519(); });
}
BENCHMARK(BM_Libsodium_Ed25519_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Note: libsodium doesn't have RSA or ECDSA-P256

#endif // ENABLE_LIBSODIUM

#ifdef ENABLE_MBEDTLS

// mbedTLS RSA-2048 Sign
static void BM_MbedTLS_RSA2048_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::mbedtls::create_rsa_2048(); });
}
BENCHMARK(BM_MbedTLS_RSA2048_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS RSA-2048 Verify
static void BM_MbedTLS_RSA2048_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::mbedtls::create_rsa_2048(); });
}
BENCHMARK(BM_MbedTLS_RSA2048_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS RSA-4096 Sign
static void BM_MbedTLS_RSA4096_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::mbedtls::create_rsa_4096(); });
}
BENCHMARK(BM_MbedTLS_RSA4096_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS RSA-4096 Verify
static void BM_MbedTLS_RSA4096_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::mbedtls::create_rsa_4096(); });
}
BENCHMARK(BM_MbedTLS_RSA4096_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS ECDSA-P256 Sign
static void BM_MbedTLS_ECDSAP256_Sign(benchmark::State& state) {
    BM_AsymmetricSign(state, []() { return crypto_bench::mbedtls::create_ecdsa_p256(); });
}
BENCHMARK(BM_MbedTLS_ECDSAP256_Sign)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// mbedTLS ECDSA-P256 Verify
static void BM_MbedTLS_ECDSAP256_Verify(benchmark::State& state) {
    BM_AsymmetricVerify(state, []() { return crypto_bench::mbedtls::create_ecdsa_p256(); });
}
BENCHMARK(BM_MbedTLS_ECDSAP256_Verify)->Arg(32)->Arg(128)->Arg(512)->Arg(1024)->Arg(4096)
    ->Unit(benchmark::kMicrosecond);

// Note: mbedTLS doesn't have Ed25519 in version 4.0.0

#endif // ENABLE_MBEDTLS

} // anonymous namespace
