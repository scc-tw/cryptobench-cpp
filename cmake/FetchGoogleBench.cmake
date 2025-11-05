# FetchGoogleBench.cmake - Fetch and configure Google Benchmark
#
# This fetches Google Benchmark for precise performance measurements

include(FetchContent)

# Google Benchmark options
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark testing" FORCE)
set(BENCHMARK_ENABLE_EXCEPTIONS OFF CACHE BOOL "Disable exceptions" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Disable install" FORCE)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES OFF CACHE BOOL "Don't download dependencies" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable GTest tests" FORCE)

# Fix for Windows regex support - force use of std::regex
if(WIN32 OR MSVC)
    set(HAVE_STD_REGEX ON CACHE BOOL "Use std::regex" FORCE)
    set(HAVE_GNU_POSIX_REGEX OFF CACHE BOOL "Don't use GNU regex" FORCE)
    set(HAVE_POSIX_REGEX OFF CACHE BOOL "Don't use POSIX regex" FORCE)
    # Ensure C++11 or later for std::regex support
    set(CMAKE_CXX_STANDARD 20 CACHE STRING "C++ standard" FORCE)
    set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "C++ standard required" FORCE)
    # Alternative: Disable regex completely if needed
    # set(BENCHMARK_ENABLE_LIBPFM OFF CACHE BOOL "Disable libpfm" FORCE)
    # set(RUN_HAVE_STD_REGEX 0 CACHE STRING "Disable regex test" FORCE)
endif()

# Additional fallback for regex issues - use no regex backend
set(BENCHMARK_USE_BUNDLED_GTEST OFF CACHE BOOL "Don't use bundled GTest" FORCE)

# Do not inject global LTO flags into Google Benchmark to avoid passing -flto to archiver

message(STATUS "Fetching Google Benchmark...")

FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.4
    GIT_SHALLOW    TRUE
    GIT_PROGRESS   TRUE
)

# Fetch and make available
FetchContent_MakeAvailable(googlebenchmark)

# Apply our optimization flags to the benchmark library
if(TARGET benchmark)
    # Apply our flags but strip any LTO options to prevent -flto reaching llvm-ar
    set(BENCH_NO_LTO_FLAGS ${CRYPTO_BENCH_CXX_FLAGS})
    list(FILTER BENCH_NO_LTO_FLAGS EXCLUDE REGEX "^-flto(=.+)?$")

    # Remove default -O? and apply filtered flags
    get_target_property(benchmark_options benchmark COMPILE_OPTIONS)
    if(benchmark_options)
        list(FILTER benchmark_options EXCLUDE REGEX "-O[0-3]")
    endif()
    target_compile_options(benchmark PRIVATE ${BENCH_NO_LTO_FLAGS})

    # Ensure IPO is disabled on this external static lib
    set_property(TARGET benchmark PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)

    # Also apply to benchmark_main if it exists
    if(TARGET benchmark_main)
        target_compile_options(benchmark_main PRIVATE ${BENCH_NO_LTO_FLAGS})
        set_property(TARGET benchmark_main PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
    endif()

    message(STATUS "Google Benchmark fetched and configured successfully")
else()
    message(FATAL_ERROR "Failed to fetch Google Benchmark")
endif()