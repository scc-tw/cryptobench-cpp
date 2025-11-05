/**
 * cryptopp_adapter.h - Crypto++ implementation of crypto_adapter interfaces
 */

#ifndef CRYPTO_BENCH_CRYPTOPP_ADAPTER_H
#define CRYPTO_BENCH_CRYPTOPP_ADAPTER_H

#include "common/crypto_adapter.h"

#ifdef ENABLE_CRYPTOPP

// Forward declarations would go here but cause conflicts with Crypto++ internals
// For now, we'll conditionally compile the advanced features

namespace crypto_bench {
namespace cryptopp {

// Hash adapters
class CryptoppSHA256 : public HashAdapter {
public:
    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "Cryptopp/SHA256"; }
};

class CryptoppSHA512 : public HashAdapter {
public:
    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }
    std::string name() const override { return "Cryptopp/SHA512"; }
};

class CryptoppSHA3_256 : public HashAdapter {
public:
    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 32; }
    std::string name() const override { return "Cryptopp/SHA3-256"; }
};

class CryptoppBLAKE2b : public HashAdapter {
public:
    void hash(const uint8_t* data, size_t len, uint8_t* output) override;
    size_t output_size() const override { return 64; }  // BLAKE2b-512
    std::string name() const override { return "Cryptopp/BLAKE2b"; }
};

// Symmetric encryption adapters
class CryptoppAES128GCM : public SymmetricAdapter {
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

    std::string name() const override { return "Cryptopp/AES-128-GCM"; }
    size_t key_size() const override { return 16; }  // 128 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

class CryptoppAES256GCM : public SymmetricAdapter {
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

    std::string name() const override { return "Cryptopp/AES-256-GCM"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits for GCM
    size_t tag_size() const override { return 16; }  // 128 bits
};

class CryptoppAES256CBC : public SymmetricAdapter {
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

    std::string name() const override { return "Cryptopp/AES-256-CBC"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 16; }   // 128 bits for CBC
    size_t tag_size() const override { return 0; }   // No tag for CBC
};

class CryptoppChaCha20Poly1305 : public SymmetricAdapter {
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

    std::string name() const override { return "Cryptopp/ChaCha20-Poly1305"; }
    size_t key_size() const override { return 32; }  // 256 bits
    size_t iv_size() const override { return 12; }   // 96 bits
    size_t tag_size() const override { return 16; }  // 128 bits
};

// Asymmetric signature adapters
class CryptoppRSA2048 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<CryptoPP::RSA::PrivateKey> private_key_;
    std::unique_ptr<CryptoPP::RSA::PublicKey> public_key_;

public:
    CryptoppRSA2048();
    ~CryptoppRSA2048();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Cryptopp/RSA-2048"; }
    size_t key_size() const override { return 2048; }
    size_t signature_size() const override { return 256; }  // 2048 bits / 8
};

class CryptoppRSA4096 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<CryptoPP::RSA::PrivateKey> private_key_;
    std::unique_ptr<CryptoPP::RSA::PublicKey> public_key_;

public:
    CryptoppRSA4096();
    ~CryptoppRSA4096();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Cryptopp/RSA-4096"; }
    size_t key_size() const override { return 4096; }
    size_t signature_size() const override { return 512; }  // 4096 bits / 8
};

class CryptoppECDSAP256 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<typename CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey> private_key_;
    std::unique_ptr<typename CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey> public_key_;

public:
    CryptoppECDSAP256();
    ~CryptoppECDSAP256();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Cryptopp/ECDSA-P256"; }
    size_t key_size() const override { return 256; }
    size_t signature_size() const override { return 72; }  // DER encoded max size
};

class CryptoppEd25519 : public AsymmetricSignAdapter {
private:
    std::unique_ptr<CryptoPP::ed25519::PrivateKey> private_key_;
    std::unique_ptr<CryptoPP::ed25519::PublicKey> public_key_;

public:
    CryptoppEd25519();
    ~CryptoppEd25519();

    void generate_keypair() override;
    void sign(
        const uint8_t* message, size_t message_len,
        uint8_t* signature, size_t* signature_len
    ) override;
    bool verify(
        const uint8_t* message, size_t message_len,
        const uint8_t* signature, size_t signature_len
    ) override;

    std::string name() const override { return "Cryptopp/Ed25519"; }
    size_t key_size() const override { return 255; }  // Curve25519
    size_t signature_size() const override { return 64; }
};

// Key exchange adapters
class CryptoppECDHP256 : public KeyExchangeAdapter {
private:
    std::unique_ptr<typename CryptoPP::ECDH<CryptoPP::ECP>::Domain> domain_;

public:
    CryptoppECDHP256();
    ~CryptoppECDHP256();

    void generate_keypair(
        uint8_t* public_key, size_t* public_key_len,
        uint8_t* private_key, size_t* private_key_len
    ) override;

    void compute_shared_secret(
        const uint8_t* our_private_key, size_t our_private_key_len,
        const uint8_t* peer_public_key, size_t peer_public_key_len,
        uint8_t* shared_secret, size_t* shared_secret_len
    ) override;

    std::string name() const override { return "Cryptopp/ECDH-P256"; }
    size_t public_key_size() const override { return 65; }   // Uncompressed point
    size_t private_key_size() const override { return 32; }  // 256 bits
    size_t shared_secret_size() const override { return 32; }
};

class CryptoppX25519 : public KeyExchangeAdapter {
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

    std::string name() const override { return "Cryptopp/X25519"; }
    size_t public_key_size() const override { return 32; }
    size_t private_key_size() const override { return 32; }
    size_t shared_secret_size() const override { return 32; }
};

// MAC adapters
class CryptoppHMACSHA256 : public MACAdapter {
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

    std::string name() const override { return "Cryptopp/HMAC-SHA256"; }
    size_t mac_size() const override { return 32; }
    size_t key_size() const override { return 32; }  // Recommended
};

class CryptoppPoly1305 : public MACAdapter {
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

    std::string name() const override { return "Cryptopp/Poly1305"; }
    size_t mac_size() const override { return 16; }
    size_t key_size() const override { return 32; }
};

// Factory functions
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

} // namespace cryptopp
} // namespace crypto_bench

#endif // ENABLE_CRYPTOPP

#endif // CRYPTO_BENCH_CRYPTOPP_ADAPTER_H