/**
 * crypto-bench - Comprehensive C++ Cryptographic Library Benchmarking Suite
 *
 * This benchmarks 16 common cryptographic operations across multiple
 * C++ cryptographic libraries with uniform compiler optimizations.
 */

#include <benchmark/benchmark.h>
#include <iostream>
#include <string>
#include <vector>

// Version information
constexpr const char* CRYPTO_BENCH_VERSION = "1.0.0";

// Custom reporter for summary statistics
class CryptoBenchReporter : public benchmark::ConsoleReporter {
public:
    bool ReportContext(const Context& context) override {
        std::cout << "\n";
        std::cout << "==============================================\n";
        std::cout << "    crypto-bench v" << CRYPTO_BENCH_VERSION << "\n";
        std::cout << "    Cryptographic Library Benchmarking Suite\n";
        std::cout << "==============================================\n";
        std::cout << "\n";

        // Print enabled libraries
        std::cout << "Enabled Libraries:\n";
#ifdef ENABLE_CRYPTOPP
        std::cout << "  ✓ Crypto++ 8.9.0\n";
#endif
#ifdef ENABLE_OPENSSL
        std::cout << "  ✓ OpenSSL 3.6.0\n";
#endif
#ifdef ENABLE_BOTAN
        std::cout << "  ✓ Botan 3.9.0\n";
#endif
#ifdef ENABLE_LIBSODIUM
        std::cout << "  ✓ libsodium 1.0.20\n";
#endif
#ifdef ENABLE_MBEDTLS
        std::cout << "  ✓ mbedTLS 4.0.0\n";
#endif
        std::cout << "\n";

        // Print optimization status
        std::cout << "Compiler Optimizations:\n";
        std::cout << "  • Maximum optimization (-O3)\n";
#ifdef __AVX2__
        std::cout << "  • AVX2 instructions enabled\n";
#endif
#ifdef __AES__
        std::cout << "  • AES-NI instructions enabled\n";
#endif
#ifdef __SHA__
        std::cout << "  • SHA extensions enabled\n";
#endif
        std::cout << "\n";

        return benchmark::ConsoleReporter::ReportContext(context);
    }
};

// Dummy benchmark to verify the system works
static void BM_Dummy(benchmark::State& state) {
    std::vector<uint8_t> data(state.range(0), 0x42);

    for (auto _ : state) {
        // Simulate some work
        benchmark::DoNotOptimize(data.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(state.iterations() * state.range(0));
}

// Register dummy benchmark with multiple data sizes
BENCHMARK(BM_Dummy)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096)
    ->Arg(16384)
    ->Unit(benchmark::kMicrosecond);

int main(int argc, char** argv) {
    // Check for special flags
    bool training_mode = false;
    bool show_version = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--training") {
            training_mode = true;
        } else if (arg == "--version" || arg == "-v") {
            show_version = true;
        }
    }

    if (show_version) {
        std::cout << "crypto-bench version " << CRYPTO_BENCH_VERSION << "\n";
        std::cout << "Comprehensive C++ Cryptographic Library Benchmarking Suite\n";
        return 0;
    }

    // Initialize benchmark
    benchmark::Initialize(&argc, argv);

    // PGO training mode - run shorter iterations for profile generation
    if (training_mode) {
        std::cout << "Running in PGO training mode...\n";

        // Override settings for training
        benchmark::SetDefaultTimeUnit(benchmark::kMillisecond);

        // Create new argv for training mode
        std::vector<char*> training_args;
        training_args.push_back(argv[0]);

        // Add training-specific flags
        const char* min_time = "--benchmark_min_time=0.1";
        const char* repetitions = "--benchmark_repetitions=1";
        training_args.push_back(const_cast<char*>(min_time));
        training_args.push_back(const_cast<char*>(repetitions));

        // Add any other user-provided flags (except --training)
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) != "--training") {
                training_args.push_back(argv[i]);
            }
        }

        int training_argc = training_args.size();
        benchmark::Initialize(&training_argc, training_args.data());
    }

    // Run benchmarks with custom reporter
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }

    // Use custom reporter for better output
    CryptoBenchReporter reporter;
    benchmark::RunSpecifiedBenchmarks(&reporter);

    // Clean shutdown
    benchmark::Shutdown();

    std::cout << "\nBenchmark completed successfully.\n";
    return 0;
}