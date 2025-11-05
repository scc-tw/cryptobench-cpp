/**
 * botan_adapter.h - Botan cryptographic library adapter
 *
 * Provides adapter classes for Botan implementations of cryptographic algorithms
 */

#ifndef CRYPTO_BENCH_BOTAN_ADAPTER_H
#define CRYPTO_BENCH_BOTAN_ADAPTER_H

#ifdef ENABLE_BOTAN

#include <memory>
#include <string>
#include <cstdint>
#include "common/crypto_adapter.h"

// Forward declare Botan types at global scope to allow pointer members without including Botan headers here
namespace Botan {
class RSA_PrivateKey;
class RSA_PublicKey;
class ECDSA_PrivateKey;
class ECDSA_PublicKey;
class Ed25519_PrivateKey;
class Ed25519_PublicKey;
}

namespace crypto_bench {
namespace botan {

// SHA-256 adapter
class BotanSHA256 : public HashAdapter {
public:
    BotanSHA256() = default;
    ~BotanSHA256() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "Botan/SHA-256"; }
};

// SHA-512 adapter
class BotanSHA512 : public HashAdapter {
public:
    BotanSHA512() = default;
    ~BotanSHA512() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }
    std::string name() const override { return "Botan/SHA-512"; }
};

// SHA3-256 adapter
class BotanSHA3_256 : public HashAdapter {
public:
    BotanSHA3_256() = default;
    ~BotanSHA3_256() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "Botan/SHA3-256"; }
};

// BLAKE2b adapter (512-bit version)
class BotanBLAKE2b : public HashAdapter {
public:
    BotanBLAKE2b() = default;
    ~BotanBLAKE2b() override = default;

    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }  // 512 bits
    std::string name() const override { return "Botan/BLAKE2b"; }
};

// AES-128-GCM adapter
class BotanAES128GCM : public SymmetricAdapter {
public:
    BotanAES128GCM() = default;
    ~BotanAES128GCM() override = default;

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

    std::string name() const override { return "Botan/AES-128-GCM"; }
    size_t key_size() const override { return 16; }  // 128 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

// AES-256-GCM adapter
class BotanAES256GCM : public SymmetricAdapter {
public:
    BotanAES256GCM() = default;
    ~BotanAES256GCM() override = default;

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

    std::string name() const override { return "Botan/AES-256-GCM"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

// AES-256-CBC adapter
class BotanAES256CBC : public SymmetricAdapter {
public:
    BotanAES256CBC() = default;
    ~BotanAES256CBC() override = default;

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

    std::string name() const override { return "Botan/AES-256-CBC"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 16; }   // 128 bits for CBC
    size_t tag_size() const override { return 0; }   // No tag for CBC
};

// ChaCha20-Poly1305 adapter
class BotanChaCha20Poly1305 : public SymmetricAdapter {
public:
    BotanChaCha20Poly1305() = default;
    ~BotanChaCha20Poly1305() override = default;

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

    std::string name() const override { return "Botan/ChaCha20-Poly1305"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits
    size_t tag_size() const override { return 16; }  // 128 bits
};

// RSA-2048 signature adapter
class BotanRSA2048 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<::Botan::RSA_PrivateKey> private_key_;
    std::unique_ptr<::Botan::RSA_PublicKey> public_key_;

public:
    BotanRSA2048();
    ~BotanRSA2048() override;

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Botan/RSA-2048"; }
    size_t key_size() const override { return 2048; }
    size_t signature_size() const override { return 256; }  // 2048 bits / 8
};

// RSA-4096 signature adapter
class BotanRSA4096 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<::Botan::RSA_PrivateKey> private_key_;
    std::unique_ptr<::Botan::RSA_PublicKey> public_key_;

public:
    BotanRSA4096();
    ~BotanRSA4096() override;

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Botan/RSA-4096"; }
    size_t key_size() const override { return 4096; }
    size_t signature_size() const override { return 512; }  // 4096 bits / 8
};

// ECDSA-P256 signature adapter
class BotanECDSAP256 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<::Botan::ECDSA_PrivateKey> private_key_;
    std::unique_ptr<::Botan::ECDSA_PublicKey> public_key_;

public:
    BotanECDSAP256();
    ~BotanECDSAP256() override;

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Botan/ECDSA-P256"; }
    size_t key_size() const override { return 256; }
    size_t signature_size() const override { return 72; }  // DER encoded max size
};

// Ed25519 signature adapter
class BotanEd25519 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<::Botan::Ed25519_PrivateKey> private_key_;
    std::unique_ptr<::Botan::Ed25519_PublicKey> public_key_;

public:
    BotanEd25519();
    ~BotanEd25519() override;

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Botan/Ed25519"; }
    size_t key_size() const override { return 255; }  // Ed25519 is based on Curve25519
    size_t signature_size() const override { return 64; }
};

// ECDH-P256 key exchange adapter
class BotanECDHP256 : public KeyExchangeAdapter {
public:
    BotanECDHP256() = default;
    ~BotanECDHP256() override = default;

    void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) override;

    void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) override;

    std::string name() const override { return "Botan/ECDH-P256"; }
    size_t public_key_size() const override { return 65; }  // Uncompressed point
    size_t private_key_size() const override { return 32; }
    size_t shared_secret_size() const override { return 32; }
};

// X25519 key exchange adapter
class BotanX25519 : public KeyExchangeAdapter {
public:
    BotanX25519() = default;
    ~BotanX25519() override = default;

    void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) override;

    void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) override;

    std::string name() const override { return "Botan/X25519"; }
    size_t public_key_size() const override { return 32; }
    size_t private_key_size() const override { return 32; }
    size_t shared_secret_size() const override { return 32; }
};

// HMAC-SHA256 adapter
class BotanHMACSHA256 : public MACAdapter {
public:
    BotanHMACSHA256() = default;
    ~BotanHMACSHA256() override = default;

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

    std::string name() const override { return "Botan/HMAC-SHA256"; }
    size_t mac_size() const override { return 32; }
    size_t key_size() const override { return 32; }  // Recommended key size
};

// Poly1305 adapter
class BotanPoly1305 : public MACAdapter {
public:
    BotanPoly1305() = default;
    ~BotanPoly1305() override = default;

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

    std::string name() const override { return "Botan/Poly1305"; }
    size_t mac_size() const override { return 16; }
    size_t key_size() const override { return 32; }
};

// Factory functions for creating hash adapters
std::unique_ptr<HashAdapter> create_sha256();
std::unique_ptr<HashAdapter> create_sha512();
std::unique_ptr<HashAdapter> create_sha3_256();
std::unique_ptr<HashAdapter> create_blake2b();

// Factory functions for symmetric encryption
std::unique_ptr<SymmetricAdapter> create_aes_128_gcm();
std::unique_ptr<SymmetricAdapter> create_aes_256_gcm();
std::unique_ptr<SymmetricAdapter> create_aes_256_cbc();
std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305();

// Factory functions for asymmetric signatures
std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048();
std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096();
std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256();
std::unique_ptr<AsymmetricSignAdapter> create_ed25519();

// Factory functions for key exchange
std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256();
std::unique_ptr<KeyExchangeAdapter> create_x25519();

// Factory functions for MAC
std::unique_ptr<MACAdapter> create_hmac_sha256();
std::unique_ptr<MACAdapter> create_poly1305();

} // namespace botan
} // namespace crypto_bench

#endif // ENABLE_BOTAN

#endif // CRYPTO_BENCH_BOTAN_ADAPTER_H