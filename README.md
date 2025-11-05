# Crypto-Bench: Comprehensive C++ Cryptographic Library Benchmarking Suite

A high-performance benchmarking suite for evaluating and comparing popular C++ cryptographic libraries in production environments.

## 📊 Benchmark Scope

This suite benchmarks the **16 most commonly used cryptographic functions** in production environments across multiple libraries:

### Hash Functions
1. **SHA-256** - Secure Hash Algorithm 256-bit
2. **SHA-512** - Secure Hash Algorithm 512-bit
3. **SHA3-256** - SHA-3 256-bit (Keccak)
4. **BLAKE2b** - BLAKE2b 512-bit hash

### Symmetric Encryption
5. **AES-128-GCM** - AES Galois/Counter Mode 128-bit
6. **AES-256-GCM** - AES Galois/Counter Mode 256-bit
7. **AES-256-CBC** - AES Cipher Block Chaining 256-bit
8. **ChaCha20-Poly1305** - ChaCha20 stream cipher with Poly1305 MAC

### Asymmetric Cryptography
9. **RSA-2048** - RSA signing/verification (2048-bit)
10. **RSA-4096** - RSA signing/verification (4096-bit)
11. **ECDSA-P256** - Elliptic Curve DSA on P-256 curve
12. **Ed25519** - EdDSA signature scheme using Curve25519

### Key Exchange & Agreement
13. **ECDH-P256** - Elliptic Curve Diffie-Hellman on P-256
14. **X25519** - Elliptic Curve Diffie-Hellman on Curve25519

### Message Authentication
15. **HMAC-SHA256** - HMAC with SHA-256
16. **Poly1305** - Poly1305 message authentication code

## 📚 Supported Libraries

| Library | Version | Description |
|---------|---------|-------------|
| **[Crypto++](https://www.cryptopp.com/)** | 8.9.0 | Comprehensive C++ crypto library |
| **[OpenSSL](https://www.openssl.org/)** | 3.6.0 | Industry-standard cryptographic library |
| **[Botan](https://botan.randombit.net/)** | 3.9.0 | Modern C++ cryptography library |
| **[libsodium](https://libsodium.gitbook.io/)** | 1.0.20 | Modern, easy-to-use crypto library |
| **[mbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/)** | 4.0.0 | Lightweight crypto library for embedded systems |

## 🔧 Build Requirements

### Prerequisites
- C++20 or later compiler (GCC 9+, Clang 10+, or MSVC 2019+)
- CMake 3.16 or later
- Git for fetching dependencies
- Python 3.6+ (for build scripts and PGO training)

### Important Build Constraints

⚠️ **Static Linking Only**: All cryptographic libraries must be:
- Compiled from source locally
- Statically linked into the benchmark binary
- **NOT** using system-installed dynamic libraries
- Built with **identical compiler optimization flags**

This ensures:
- **Fair comparison**: All libraries benefit from the same compiler optimizations
- **Reproducible results**: Performance depends only on algorithm implementation, not on build variations
- **No external dependencies**: Results are independent of OS or system library versions
- **Compiler-driven performance**: We measure the efficiency of the crypto algorithms when optimized by the same compiler

## 🚀 Building from Source

### Quick Start

```bash
# Clone the repository
git clone https://github.com/scc-tw/cryptobench-cpp.git
cd cryptobench-cpp

# Create build directory
mkdir build && cd build

# Configure with CMake (Release mode with all optimizations)
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-O3 -march=native -mtune=native" \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DENABLE_LTO=ON \
    -DENABLE_PGO=ON

# Build
make -j$(nproc)

# Run benchmarks
./crypto-bench
```

### Detailed CMake Configuration

The project uses a bottom-up CMake build system that applies **compiler optimizations uniformly** to all libraries:

```cmake
# Compiler optimization flags (applied to ALL libraries equally)
-O3                          # Maximum optimization level
-march=native                # CPU-specific optimizations
-mtune=native               # CPU-specific tuning
-flto                       # Link-Time Optimization
-fprofile-generate/use      # Profile-Guided Optimization
-funroll-loops              # Loop unrolling
-fomit-frame-pointer        # Omit frame pointers

# These flags ensure the compiler can optimize each library's
# algorithms to their fullest potential on your specific CPU
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_CRYPTOPP` | ON | Build and benchmark Crypto++ 8.9.0 |
| `BUILD_OPENSSL` | ON | Build and benchmark OpenSSL 3.6.0 |
| `BUILD_BOTAN` | ON | Build and benchmark Botan 3.9.0 |
| `BUILD_LIBSODIUM` | ON | Build and benchmark libsodium 1.0.20 |
| `BUILD_MBEDTLS` | ON | Build and benchmark mbedTLS 4.0.0 |
| `ENABLE_LTO` | ON | Enable Link-Time Optimization |
| `ENABLE_PGO` | OFF | Enable Profile-Guided Optimization |
| `ENABLE_NATIVE` | ON | Enable CPU-specific optimizations |

### Profile-Guided Optimization (PGO)

For maximum performance, build with PGO:

```bash
# Step 1: Build with profiling instrumentation
cmake .. -DENABLE_PGO=ON -DPGO_PHASE=GENERATE
make -j$(nproc)

# Step 2: Run training workload
./crypto-bench --training

# Step 3: Rebuild using profile data
cmake .. -DENABLE_PGO=ON -DPGO_PHASE=USE
make clean && make -j$(nproc)

# Step 4: Run final benchmarks
./crypto-bench
```

## 📊 Benchmarking with Google Benchmark

This project uses [Google Benchmark](https://github.com/google/benchmark) for precise performance measurements.

### Running Benchmarks

```bash
# Run all benchmarks
./crypto-bench

# Run specific library benchmarks
./crypto-bench --benchmark_filter="Cryptopp/*"
./crypto-bench --benchmark_filter="OpenSSL/*"
./crypto-bench --benchmark_filter="Botan/*"
./crypto-bench --benchmark_filter="libsodium/*"
./crypto-bench --benchmark_filter="mbedTLS/*"

# Run specific algorithm benchmarks
./crypto-bench --benchmark_filter="*/SHA256/*"
./crypto-bench --benchmark_filter="*/AES256GCM/*"

# Output formats
./crypto-bench --benchmark_format=json > results.json
./crypto-bench --benchmark_format=csv > results.csv

# Advanced options
./crypto-bench --benchmark_repetitions=10        # Multiple runs for stability
./crypto-bench --benchmark_report_aggregates_only # Only show mean/median/stddev
./crypto-bench --benchmark_time_unit=ns          # Report in nanoseconds
```

### Benchmark Metrics

For each cryptographic operation, we measure:
- **Throughput** (MB/s) - Data processed per second
- **Latency** (ns) - Time for single operation
- **Operations/sec** - Number of operations per second
- **CPU Cycles** - CPU cycles per byte (when available)

### Sample Output

```
--------------------------------------------------------------------
Benchmark                          Time             CPU   Iterations
--------------------------------------------------------------------
Cryptopp/SHA256/4096            2154 ns         2154 ns       325021   1.81GB/s
OpenSSL/SHA256/4096             1876 ns         1876 ns       373213   2.08GB/s
Botan/SHA256/4096               2043 ns         2043 ns       342658   1.91GB/s
libsodium/SHA256/4096           1923 ns         1923 ns       364102   2.03GB/s
mbedTLS/SHA256/4096             2287 ns         2287 ns       306142   1.71GB/s

Cryptopp/AES256GCM/4096         3421 ns         3421 ns       204587   1.14GB/s
OpenSSL/AES256GCM/4096          2156 ns         2156 ns       324821   1.81GB/s
Botan/AES256GCM/4096            2893 ns         2893 ns       241876   1.35GB/s
```

## 🏗️ Project Structure

```
crypto-bench/
├── CMakeLists.txt              # Main CMake configuration
├── cmake/                      # CMake modules and scripts
│   ├── FetchCryptopp.cmake    # Fetch and build Crypto++ 8.9.0
│   ├── FetchOpenSSL.cmake     # Fetch and build OpenSSL 3.6.0
│   ├── FetchBotan.cmake       # Fetch and build Botan 3.9.0
│   ├── FetchLibsodium.cmake   # Fetch and build libsodium 1.0.20
│   ├── FetchMbedTLS.cmake     # Fetch and build mbedTLS 4.0.0
│   └── FetchGoogleBench.cmake # Fetch Google Benchmark
├── src/
│   ├── main.cpp               # Benchmark main entry point
│   ├── benchmarks/
│   │   ├── hash/              # Hash function benchmarks
│   │   ├── symmetric/         # Symmetric encryption benchmarks
│   │   ├── asymmetric/        # Asymmetric crypto benchmarks
│   │   ├── kex/               # Key exchange benchmarks
│   │   └── mac/               # MAC benchmarks
│   └── adapters/              # Library-specific adapters
│       ├── cryptopp_adapter.h
│       ├── openssl_adapter.h
│       ├── botan_adapter.h
│       ├── sodium_adapter.h
│       └── mbedtls_adapter.h
└── scripts/
    ├── run_benchmarks.py      # Automated benchmark runner
    └── analyze_results.py     # Result analysis and visualization
```

## 📈 Interpreting Results

### What We Measure

This benchmark suite measures **pure algorithmic performance** when all libraries are optimized equally by the compiler. The results show:

- **Algorithm Efficiency**: How well each library's implementation performs
- **Compiler Optimization Impact**: How effectively the compiler can optimize each library's code
- **Hardware Utilization**: How well each implementation uses CPU features (when compiler can detect them)

### Performance Factors

Results may vary based on:
- **CPU Architecture** - Intel vs AMD, generation, cache sizes
- **CPU Features** - AES-NI, AVX2, SHA extensions (compiler auto-detects via `-march=native`)
- **Compiler Version** - Different GCC/Clang versions may optimize differently
- **Implementation Quality** - The algorithmic efficiency of each library's code

### Best Practices

1. **Isolate CPU Cores** - Use `taskset` on Linux for consistent results
2. **Disable Turbo/Boost** - For reproducible measurements
3. **Multiple Runs** - Use `--benchmark_repetitions` for stability
4. **Warm-up** - First run may be slower due to cache effects

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Adding new cryptographic libraries
- Adding new benchmark algorithms
- Improving build system
- Performance optimizations

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 References

- [Google Benchmark Documentation](https://github.com/google/benchmark/blob/main/docs/user_guide.md)
- [CMake Best Practices](https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html)
- [Crypto++ 8.9.0 Release Notes](https://www.cryptopp.com/release890.html)
- [OpenSSL 3.6.0 Documentation](https://www.openssl.org/docs/man3.6/)
- [Botan 3.9.0 Documentation](https://botan.randombit.net/handbook/)
- [libsodium 1.0.20 Documentation](https://doc.libsodium.org/)
- [mbedTLS 4.0.0 Documentation](https://mbed-tls.readthedocs.io/)

## ⚡ Benchmark Execution Tips

**Important**: This benchmark suite relies exclusively on **compiler optimizations**, not OS-level optimizations. All libraries are compiled with identical compiler flags to ensure fair comparison.

### Ensuring Consistent Results

1. **Multiple Runs**: Execute benchmarks multiple times for statistical stability
   ```bash
   ./crypto-bench --benchmark_repetitions=10
   ```

2. **Warm-up Phase**: First execution may be slower due to cold cache
   ```bash
   # Run once to warm up, then collect actual results
   ./crypto-bench --benchmark_filter="*/warmup"
   ./crypto-bench
   ```

3. **Minimize System Interference**:
   - Close unnecessary applications
   - Run benchmarks when system is idle
   - Use `--benchmark_report_aggregates_only` for cleaner output

4. **Verify Optimization Flags**: Ensure all libraries were built with same flags
   ```bash
   # Check that binary includes optimizations
   objdump -d crypto-bench | grep -c "vpaes\|aesni"  # Check for AES-NI instructions
   ```

## 🐛 Troubleshooting

### Common Issues

1. **Library Version Conflicts**
   - Ensure no system libraries are being linked
   - Check with `ldd crypto-bench` - should show minimal dependencies

2. **Build Failures**
   - Clear build directory and CMake cache
   - Verify compiler supports C++20
   - Check available memory for LTO builds (may require 8GB+)

3. **Inconsistent Results**
   - Disable CPU frequency scaling
   - Run on isolated cores
   - Increase repetitions for stability

### Getting Help

- Open an issue on GitHub
- Check existing issues for solutions
- Provide system info, compiler version, and error logs