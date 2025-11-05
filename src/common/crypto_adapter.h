/**
 * crypto_adapter.h - Abstract interfaces for cryptographic operations
 *
 * This file defines the common interfaces that all cryptographic libraries
 * must implement. This ensures fair comparison and consistent API usage.
 */

#ifndef CRYPTO_BENCH_CRYPTO_ADAPTER_H
#define CRYPTO_BENCH_CRYPTO_ADAPTER_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>

namespace crypto_bench {

// Hash function interface
class HashAdapter {
public:
    virtual ~HashAdapter() = default;

    // Hash data and store result in output buffer
    // output buffer must be at least output_size() bytes
    virtual void hash(const uint8_t* data, size_t len, uint8_t* output) = 0;

    // Get the output size in bytes for this hash function
    virtual size_t output_size() const = 0;

    // Get the name of this hash algorithm
    virtual std::string name() const = 0;
};

// Symmetric encryption interface (for AES-GCM, ChaCha20-Poly1305, etc.)
class SymmetricAdapter {
public:
    virtual ~SymmetricAdapter() = default;

    // Encrypt plaintext with authenticated encryption (AEAD)
    // For GCM/Poly1305: tag is appended or separate depending on implementation
    virtual void encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,  // Additional authenticated data
        uint8_t* ciphertext,
        uint8_t* tag, size_t tag_len
    ) = 0;

    // Decrypt ciphertext with authenticated encryption (AEAD)
    virtual bool decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* plaintext
    ) = 0;

    // For non-AEAD modes like CBC (no authentication)
    virtual void encrypt_cbc(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        uint8_t* ciphertext
    ) {
        // Default implementation throws - override for CBC modes
        throw std::runtime_error("CBC mode not supported");
    }

    virtual void decrypt_cbc(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        uint8_t* plaintext
    ) {
        // Default implementation throws - override for CBC modes
        throw std::runtime_error("CBC mode not supported");
    }

    virtual std::string name() const = 0;
    virtual size_t key_size() const = 0;
    virtual size_t iv_size() const = 0;
    virtual size_t tag_size() const = 0;
};

// Asymmetric signature interface (RSA, ECDSA, Ed25519)
class AsymmetricSignAdapter {
public:
    virtual ~AsymmetricSignAdapter() = default;

    // Generate a key pair
    virtual void generate_keypair() = 0;

    // Sign message with private key
    virtual void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) = 0;

    // Verify signature with public key
    virtual bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) = 0;

    virtual std::string name() const = 0;
    virtual size_t key_size() const = 0;  // Key size in bits
    virtual size_t signature_size() const = 0;  // Max signature size in bytes
};

// Key exchange interface (ECDH, X25519)
class KeyExchangeAdapter {
public:
    virtual ~KeyExchangeAdapter() = default;

    // Generate a key pair for this party
    virtual void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) = 0;

    // Compute shared secret using our private key and peer's public key
    virtual void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) = 0;

    virtual std::string name() const = 0;
    virtual size_t public_key_size() const = 0;
    virtual size_t private_key_size() const = 0;
    virtual size_t shared_secret_size() const = 0;
};

// Message Authentication Code interface (HMAC, Poly1305)
class MACAdapter {
public:
    virtual ~MACAdapter() = default;

    // Compute MAC of message
    virtual void compute(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        uint8_t* mac, size_t mac_len
    ) = 0;

    // Verify MAC of message
    virtual bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* mac, size_t mac_len
    ) = 0;

    virtual std::string name() const = 0;
    virtual size_t mac_size() const = 0;
    virtual size_t key_size() const = 0;  // Recommended key size
};

// Factory functions for creating adapters
// These will be implemented by each library's adapter
namespace factory {
    // Hash functions
    std::unique_ptr<HashAdapter> create_sha256();
    std::unique_ptr<HashAdapter> create_sha512();
    std::unique_ptr<HashAdapter> create_sha3_256();
    std::unique_ptr<HashAdapter> create_blake2b();

    // Symmetric encryption
    std::unique_ptr<SymmetricAdapter> create_aes_128_gcm();
    std::unique_ptr<SymmetricAdapter> create_aes_256_gcm();
    std::unique_ptr<SymmetricAdapter> create_aes_256_cbc();
    std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305();

    // Asymmetric signatures
    std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048();
    std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096();
    std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256();
    std::unique_ptr<AsymmetricSignAdapter> create_ed25519();

    // Key exchange
    std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256();
    std::unique_ptr<KeyExchangeAdapter> create_x25519();

    // MAC
    std::unique_ptr<MACAdapter> create_hmac_sha256();
    std::unique_ptr<MACAdapter> create_poly1305();
}

} // namespace crypto_bench

#endif // CRYPTO_BENCH_CRYPTO_ADAPTER_H