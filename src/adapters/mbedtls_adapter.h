/**
 * mbedtls_adapter.h - mbedTLS cryptographic library adapter
 *
 * Provides adapter classes for mbedTLS implementations of cryptographic algorithms
 */

#ifndef CRYPTO_BENCH_MBEDTLS_ADAPTER_H
#define CRYPTO_BENCH_MBEDTLS_ADAPTER_H

#ifdef ENABLE_MBEDTLS

#include <memory>
#include <string>
#include <cstdint>
#include <psa/crypto.h>
#include "common/crypto_adapter.h"

namespace crypto_bench {
namespace mbedtls {

// SHA-256 adapter
class MbedTLSSHA256 : public HashAdapter {
public:
    MbedTLSSHA256() = default;
    ~MbedTLSSHA256() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "mbedTLS/SHA-256"; }
};

// SHA-512 adapter
class MbedTLSSHA512 : public HashAdapter {
public:
    MbedTLSSHA512() = default;
    ~MbedTLSSHA512() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }
    std::string name() const override { return "mbedTLS/SHA-512"; }
};

// SHA3-256 adapter
class MbedTLSSHA3_256 : public HashAdapter {
public:
    MbedTLSSHA3_256() = default;
    ~MbedTLSSHA3_256() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "mbedTLS/SHA3-256"; }
};

// Note: mbedTLS doesn't have native BLAKE2b support
// We'll skip BLAKE2b for mbedTLS

// Symmetric encryption adapters
class MbedTLSAES128GCM : public SymmetricAdapter {
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

    std::string name() const override { return "mbedTLS/AES-128-GCM"; }
    size_t key_size() const override { return 16; }  // 128 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

class MbedTLSAES256GCM : public SymmetricAdapter {
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

    std::string name() const override { return "mbedTLS/AES-256-GCM"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

class MbedTLSAES256CBC : public SymmetricAdapter {
public:
    void encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext,
        uint8_t* tag, size_t tag_len
    ) override {
        throw std::runtime_error("Use encrypt_cbc for CBC mode");
    }

    bool decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* plaintext
    ) override {
        throw std::runtime_error("Use decrypt_cbc for CBC mode");
    }

    void encrypt_cbc(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        uint8_t* ciphertext
    ) override;

    void decrypt_cbc(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* key, size_t key_len,
        const uint8_t* iv, size_t iv_len,
        uint8_t* plaintext
    ) override;

    std::string name() const override { return "mbedTLS/AES-256-CBC"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 16; }   // 128 bits for CBC
    size_t tag_size() const override { return 0; }   // No tag for CBC
};

class MbedTLSChaCha20Poly1305 : public SymmetricAdapter {
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

    std::string name() const override { return "mbedTLS/ChaCha20-Poly1305"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits
    size_t tag_size() const override { return 16; }  // 128 bits
};

// Asymmetric signature adapters
class MbedTLSRSA2048 : public AsymmetricSignAdapter {
private:
    psa_key_id_t key_id_;

public:
    MbedTLSRSA2048();
    ~MbedTLSRSA2048();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "mbedTLS/RSA-2048"; }
    size_t key_size() const override { return 2048; }
    size_t signature_size() const override { return 256; }  // 2048 bits / 8
};

class MbedTLSRSA4096 : public AsymmetricSignAdapter {
private:
    psa_key_id_t key_id_;

public:
    MbedTLSRSA4096();
    ~MbedTLSRSA4096();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "mbedTLS/RSA-4096"; }
    size_t key_size() const override { return 4096; }
    size_t signature_size() const override { return 512; }  // 4096 bits / 8
};

class MbedTLSECDSAP256 : public AsymmetricSignAdapter {
private:
    psa_key_id_t key_id_;

public:
    MbedTLSECDSAP256();
    ~MbedTLSECDSAP256();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "mbedTLS/ECDSA-P256"; }
    size_t key_size() const override { return 256; }
    size_t signature_size() const override { return 72; }  // DER encoded max size
};

// Note: mbedTLS doesn't have Ed25519 in version 4.0.0
// We'll skip Ed25519 for mbedTLS

// Key exchange adapters
class MbedTLSECDHP256 : public KeyExchangeAdapter {
private:
    psa_key_id_t key_id_;

public:
    MbedTLSECDHP256();
    ~MbedTLSECDHP256();

    void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) override;

    void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) override;

    std::string name() const override { return "mbedTLS/ECDH-P256"; }
    size_t public_key_size() const override { return 65; }   // Uncompressed point
    size_t private_key_size() const override { return 32; }  // 256 bits
    size_t shared_secret_size() const override { return 32; }
};

// Note: mbedTLS doesn't have X25519 in version 4.0.0
// We'll skip X25519 for mbedTLS

// MAC adapters
class MbedTLSHMACSHA256 : public MACAdapter {
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

    std::string name() const override { return "mbedTLS/HMAC-SHA256"; }
    size_t mac_size() const override { return 32; }
    size_t key_size() const override { return 32; }  // Recommended
};

// Note: mbedTLS doesn't have standalone Poly1305 in version 4.0.0
// Poly1305 is only available as part of ChaCha20-Poly1305
// We'll skip standalone Poly1305 for mbedTLS

// Factory functions for creating hash adapters
std::unique_ptr<HashAdapter> create_sha256();
std::unique_ptr<HashAdapter> create_sha512();
std::unique_ptr<HashAdapter> create_sha3_256();
// No BLAKE2b factory for mbedTLS

// Symmetric encryption factory functions
std::unique_ptr<SymmetricAdapter> create_aes_128_gcm();
std::unique_ptr<SymmetricAdapter> create_aes_256_gcm();
std::unique_ptr<SymmetricAdapter> create_aes_256_cbc();
std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305();

// Asymmetric signature factory functions
std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048();
std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096();
std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256();
// No Ed25519 factory for mbedTLS

// Key exchange factory functions
std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256();
// No X25519 factory for mbedTLS

// MAC factory functions
std::unique_ptr<MACAdapter> create_hmac_sha256();
// No standalone Poly1305 factory for mbedTLS

} // namespace mbedtls
} // namespace crypto_bench

#endif // ENABLE_MBEDTLS

#endif // CRYPTO_BENCH_MBEDTLS_ADAPTER_H