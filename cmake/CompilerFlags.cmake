# CompilerFlags.cmake - Uniform compiler optimization flags for all libraries
#
# This file defines optimization flags that are applied uniformly to ALL
# cryptographic libraries to ensure fair performance comparison

# Initialize flag list
set(CRYPTO_BENCH_CXX_FLAGS "")
set(CRYPTO_BENCH_C_FLAGS "")

# Base optimization flags (applicable to all compilers)
list(APPEND CRYPTO_BENCH_CXX_FLAGS
    -O3                         # Maximum optimization level
    -fomit-frame-pointer        # Omit frame pointers for better performance
    -funroll-loops              # Enable loop unrolling
)

# Copy C++ flags to C flags (for libraries that use C)
set(CRYPTO_BENCH_C_FLAGS ${CRYPTO_BENCH_CXX_FLAGS})

# Platform and compiler specific flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    list(APPEND CRYPTO_BENCH_CXX_FLAGS
        -Wall                   # Enable all warnings
        -Wextra                 # Enable extra warnings
        -Wno-unused-parameter   # Disable unused parameter warnings
        -Wno-unused-variable    # Disable unused variable warnings
        -fno-strict-aliasing    # Disable strict aliasing optimizations
    )

    # Additional optimization flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        # GCC-specific flags
        list(APPEND CRYPTO_BENCH_CXX_FLAGS
            -finline-functions      # Inline functions marked inline
            -finline-limit=1000     # Increase inline limit (GCC only)
        )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Clang-specific flags
        list(APPEND CRYPTO_BENCH_CXX_FLAGS
            -finline-functions      # Inline functions marked inline
            # Clang doesn't support -finline-limit, uses -finline-hint-functions instead
        )
    endif()

    # Note: We avoid -ffast-math for cryptographic operations as it can affect accuracy

elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    list(APPEND CRYPTO_BENCH_CXX_FLAGS
        /O2                     # Maximum optimization
        /Ob2                    # Inline expansion level 2
        /Oi                     # Enable intrinsic functions
        /Ot                     # Favor fast code
        /Oy                     # Omit frame pointers
        /GT                     # Enable fiber-safe optimizations
        /GL                     # Whole program optimization
    )
endif()

# Native CPU optimizations (when ENABLE_NATIVE=ON)
if(ENABLE_NATIVE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        list(APPEND CRYPTO_BENCH_CXX_FLAGS
            -march=native       # Optimize for the host CPU architecture
            -mtune=native       # Tune for the host CPU
        )
        message(STATUS "Native CPU optimizations enabled (-march=native)")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        # MSVC doesn't have direct equivalent to -march=native
        # Use /arch:AVX2 if available
        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_AVX2)
        if(COMPILER_SUPPORTS_AVX2)
            list(APPEND CRYPTO_BENCH_CXX_FLAGS /arch:AVX2)
            message(STATUS "AVX2 optimizations enabled")
        endif()
    endif()
endif()

# Link-Time Optimization (when ENABLE_LTO=ON)
if(ENABLE_LTO)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        list(APPEND CRYPTO_BENCH_CXX_FLAGS -flto)
        list(APPEND CRYPTO_BENCH_C_FLAGS -flto)

        # Also set for executable and shared linker
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto")
        message(STATUS "Link-Time Optimization enabled (GCC)")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        list(APPEND CRYPTO_BENCH_CXX_FLAGS -flto)
        list(APPEND CRYPTO_BENCH_C_FLAGS -flto)

        # For Clang, especially on macOS, we need special handling
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto")
        # Don't set -flto for static linker flags on macOS
        if(NOT APPLE)
            set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -flto")
        endif()

        # Interprocedural optimization will be set per-target

        # On macOS with Clang, we need to use llvm-ar for LTO archives
        if(APPLE)
            # Try to find llvm-ar
            find_program(LLVM_AR llvm-ar)
            if(LLVM_AR)
                set(CMAKE_AR ${LLVM_AR})
                message(STATUS "Using llvm-ar for LTO: ${LLVM_AR}")
            else()
                # If llvm-ar not found, disable LTO for static libraries
                message(WARNING "llvm-ar not found, LTO may not work for static libraries")
                set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
            endif()
        endif()

        message(STATUS "Link-Time Optimization enabled (Clang)")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        # MSVC LTO is enabled with /GL (set above) and /LTCG (linker)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LTCG")
        set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /LTCG")
        message(STATUS "Link-Time Code Generation enabled")
    endif()
endif()

# Profile-Guided Optimization (when ENABLE_PGO=ON)
if(ENABLE_PGO)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        if(PGO_PHASE STREQUAL "GENERATE")
            list(APPEND CRYPTO_BENCH_CXX_FLAGS -fprofile-generate)
            list(APPEND CRYPTO_BENCH_C_FLAGS -fprofile-generate)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-generate")
            message(STATUS "PGO Generation phase enabled")
        elseif(PGO_PHASE STREQUAL "USE")
            list(APPEND CRYPTO_BENCH_CXX_FLAGS -fprofile-use -fprofile-correction)
            list(APPEND CRYPTO_BENCH_C_FLAGS -fprofile-use -fprofile-correction)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-use")
            message(STATUS "PGO Use phase enabled")
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        if(PGO_PHASE STREQUAL "GENERATE")
            list(APPEND CRYPTO_BENCH_CXX_FLAGS -fprofile-generate)
            list(APPEND CRYPTO_BENCH_C_FLAGS -fprofile-generate)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-generate")
            message(STATUS "PGO Generation phase enabled")
        elseif(PGO_PHASE STREQUAL "USE")
            # For Clang, need to specify the profile data file
            list(APPEND CRYPTO_BENCH_CXX_FLAGS -fprofile-use=${CMAKE_BINARY_DIR}/default.profdata)
            list(APPEND CRYPTO_BENCH_C_FLAGS -fprofile-use=${CMAKE_BINARY_DIR}/default.profdata)
            message(STATUS "PGO Use phase enabled with profile data")
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        if(PGO_PHASE STREQUAL "GENERATE")
            list(APPEND CRYPTO_BENCH_CXX_FLAGS /GL)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG /GENPROFILE")
            message(STATUS "PGO Generation phase enabled (MSVC)")
        elseif(PGO_PHASE STREQUAL "USE")
            list(APPEND CRYPTO_BENCH_CXX_FLAGS /GL)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG /USEPROFILE")
            message(STATUS "PGO Use phase enabled (MSVC)")
        endif()
    endif()
endif()

# Convert lists to strings for some build systems that need strings
string(REPLACE ";" " " CRYPTO_BENCH_CXX_FLAGS_STR "${CRYPTO_BENCH_CXX_FLAGS}")
string(REPLACE ";" " " CRYPTO_BENCH_C_FLAGS_STR "${CRYPTO_BENCH_C_FLAGS}")

# Function to apply flags to a target
function(apply_crypto_bench_flags target)
    target_compile_options(${target} PRIVATE ${CRYPTO_BENCH_CXX_FLAGS})

    # Enable IPO on this target when LTO is enabled
    if(ENABLE_LTO)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()

    # Set C flags for targets that use C
    get_target_property(target_type ${target} TYPE)
    get_target_property(sources ${target} SOURCES)
    foreach(source ${sources})
        get_filename_component(ext ${source} EXT)
        if(ext STREQUAL ".c")
            set_source_files_properties(${source} PROPERTIES
                COMPILE_FLAGS "${CRYPTO_BENCH_C_FLAGS_STR}")
            break()
        endif()
    endforeach()
endfunction()

# Print final flags for debugging
message(STATUS "crypto-bench C++ optimization flags: ${CRYPTO_BENCH_CXX_FLAGS_STR}")
message(STATUS "crypto-bench C optimization flags: ${CRYPTO_BENCH_C_FLAGS_STR}")