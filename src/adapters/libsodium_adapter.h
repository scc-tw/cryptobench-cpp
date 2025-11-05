/**
 * libsodium_adapter.h - libsodium cryptographic library adapter
 *
 * Provides adapter classes for libsodium implementations of cryptographic algorithms
 */

#ifndef CRYPTO_BENCH_LIBSODIUM_ADAPTER_H
#define CRYPTO_BENCH_LIBSODIUM_ADAPTER_H

#ifdef ENABLE_LIBSODIUM

#include <memory>
#include <string>
#include <cstdint>
#include "common/crypto_adapter.h"

namespace crypto_bench {
namespace libsodium {

// Hash function adapters
class LibsodiumSHA256 : public HashAdapter {
public:
    LibsodiumSHA256() = default;
    ~LibsodiumSHA256() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "libsodium/SHA-256"; }
};

class LibsodiumSHA512 : public HashAdapter {
public:
    LibsodiumSHA512() = default;
    ~LibsodiumSHA512() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }
    std::string name() const override { return "libsodium/SHA-512"; }
};

// Note: libsodium doesn't have SHA3-256, but has BLAKE2b
class LibsodiumBLAKE2b : public HashAdapter {
public:
    LibsodiumBLAKE2b() = default;
    ~LibsodiumBLAKE2b() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }  // BLAKE2b-512
    std::string name() const override { return "libsodium/BLAKE2b"; }
};

// Symmetric encryption adapters
class LibsodiumAES256GCM : public SymmetricAdapter {
public:
    void encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext,
        uint8_t* tag, size_t tag_len
    ) override;

    bool decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* plaintext
    ) override;

    std::string name() const override { return "libsodium/AES-256-GCM"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

class LibsodiumChaCha20Poly1305 : public SymmetricAdapter {
public:
    void encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext,
        uint8_t* tag, size_t tag_len
    ) override;

    bool decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* plaintext
    ) override;

    std::string name() const override { return "libsodium/ChaCha20-Poly1305"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits
    size_t tag_size() const override { return 16; }  // 128 bits
};

// Note: libsodium doesn't have AES-128-GCM or AES-256-CBC in the high-level API
// We'll skip those for libsodium

// Asymmetric signature adapters
class LibsodiumEd25519 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<uint8_t[]> public_key_;
    std::unique_ptr<uint8_t[]> private_key_;

public:
    LibsodiumEd25519();
    ~LibsodiumEd25519();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "libsodium/Ed25519"; }
    size_t key_size() const override { return 255; }  // Curve25519
    size_t signature_size() const override { return 64; }
};

// Note: libsodium doesn't have RSA or ECDSA-P256
// We'll skip those for libsodium

// Key exchange adapters
class LibsodiumX25519 : public KeyExchangeAdapter {
public:
    void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) override;

    void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) override;

    std::string name() const override { return "libsodium/X25519"; }
    size_t public_key_size() const override { return 32; }
    size_t private_key_size() const override { return 32; }
    size_t shared_secret_size() const override { return 32; }
};

// Note: libsodium doesn't have ECDH-P256
// We'll skip that for libsodium

// MAC adapters
class LibsodiumHMACSHA256 : public MACAdapter {
public:
    void compute(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        uint8_t* mac, size_t mac_len
    ) override;

    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* mac, size_t mac_len
    ) override;

    std::string name() const override { return "libsodium/HMAC-SHA256"; }
    size_t mac_size() const override { return 32; }
    size_t key_size() const override { return 32; }  // Recommended
};

class LibsodiumHMACSHA512 : public MACAdapter {
public:
    void compute(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        uint8_t* mac, size_t mac_len
    ) override;

    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* mac, size_t mac_len
    ) override;

    std::string name() const override { return "libsodium/HMAC-SHA512"; }
    size_t mac_size() const override { return 64; }
    size_t key_size() const override { return 64; }  // Recommended
};

class LibsodiumPoly1305 : public MACAdapter {
public:
    void compute(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        uint8_t* mac, size_t mac_len
    ) override;

    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* mac, size_t mac_len
    ) override;

    std::string name() const override { return "libsodium/Poly1305"; }
    size_t mac_size() const override { return 16; }
    size_t key_size() const override { return 32; }
};

// Factory functions for creating hash adapters
std::unique_ptr<HashAdapter> create_sha256();
std::unique_ptr<HashAdapter> create_sha512();
// No SHA3-256 factory for libsodium
std::unique_ptr<HashAdapter> create_blake2b();

// Symmetric encryption factory functions
// No AES-128-GCM factory for libsodium
std::unique_ptr<SymmetricAdapter> create_aes_256_gcm();
// No AES-256-CBC factory for libsodium
std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305();

// Asymmetric signature factory functions
// No RSA factories for libsodium
// No ECDSA-P256 factory for libsodium
std::unique_ptr<AsymmetricSignAdapter> create_ed25519();

// Key exchange factory functions
// No ECDH-P256 factory for libsodium
std::unique_ptr<KeyExchangeAdapter> create_x25519();

// MAC factory functions
std::unique_ptr<MACAdapter> create_hmac_sha256();
std::unique_ptr<MACAdapter> create_hmac_sha512(); // Extra function for libsodium
std::unique_ptr<MACAdapter> create_poly1305();

} // namespace libsodium
} // namespace crypto_bench

#endif // ENABLE_LIBSODIUM

#endif // CRYPTO_BENCH_LIBSODIUM_ADAPTER_H
