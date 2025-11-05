/**
 * openssl_adapter.cpp - OpenSSL implementation of crypto_adapter interfaces
 */

#include "openssl_adapter.h"

#ifdef ENABLE_OPENSSL

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <stdexcept>
#include <cstring>
#include <memory>

namespace crypto_bench {
namespace openssl {

// =============================================================================
// Hash Function Implementations
// =============================================================================

void OpenSSLSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 hash failed");
    }

    EVP_MD_CTX_free(ctx);
}

void OpenSSLSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA512 hash failed");
    }

    EVP_MD_CTX_free(ctx);
}

void OpenSSLSHA3_256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-256 hash failed");
    }

    EVP_MD_CTX_free(ctx);
}

void OpenSSLBLAKE2b::hash(const uint8_t* data, size_t len, uint8_t* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("BLAKE2b hash failed");
    }

    EVP_MD_CTX_free(ctx);
}

// =============================================================================
// Symmetric Encryption Implementations
// =============================================================================

void OpenSSLAES128GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-128-GCM encrypt init failed");
    }

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-128-GCM AAD failed");
        }
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-128-GCM encrypt failed");
    }

    EVP_CIPHER_CTX_free(ctx);
}

bool OpenSSLAES128GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    return ret > 0;
}

// Similar implementations for AES256GCM, AES256CBC, and ChaCha20Poly1305
// For brevity, I'll provide stub implementations that throw

void OpenSSLAES256GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    throw std::runtime_error("OpenSSL AES-256-GCM encrypt not implemented yet");
}

bool OpenSSLAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    throw std::runtime_error("OpenSSL AES-256-GCM decrypt not implemented yet");
}

void OpenSSLAES256CBC::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    // CBC mode doesn't use AAD or tags - use encrypt_cbc instead
    encrypt_cbc(plaintext, plaintext_len, key, key_len, iv, iv_len, ciphertext);
}

bool OpenSSLAES256CBC::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    // CBC mode doesn't use AAD or tags - use decrypt_cbc instead
    decrypt_cbc(ciphertext, ciphertext_len, key, key_len, iv, iv_len, plaintext);
    return true;
}

void OpenSSLAES256CBC::encrypt_cbc(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* ciphertext
) {
    throw std::runtime_error("OpenSSL AES-256-CBC encrypt not implemented yet");
}

void OpenSSLAES256CBC::decrypt_cbc(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext
) {
    throw std::runtime_error("OpenSSL AES-256-CBC decrypt not implemented yet");
}

void OpenSSLChaCha20Poly1305::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    throw std::runtime_error("OpenSSL ChaCha20-Poly1305 encrypt not implemented yet");
}

bool OpenSSLChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    throw std::runtime_error("OpenSSL ChaCha20-Poly1305 decrypt not implemented yet");
}

// =============================================================================
// Asymmetric Signature Implementations
// =============================================================================

OpenSSLRSA2048::OpenSSLRSA2048() : keypair_(nullptr) {}

OpenSSLRSA2048::~OpenSSLRSA2048() {
    if (keypair_) {
        EVP_PKEY_free(keypair_);
    }
}

void OpenSSLRSA2048::generate_keypair() {
    throw std::runtime_error("OpenSSL RSA-2048 key generation not implemented yet");
}

void OpenSSLRSA2048::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    throw std::runtime_error("OpenSSL RSA-2048 signing not implemented yet");
}

bool OpenSSLRSA2048::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    throw std::runtime_error("OpenSSL RSA-2048 verification not implemented yet");
}

// Similar stub implementations for other asymmetric algorithms
OpenSSLRSA4096::OpenSSLRSA4096() : keypair_(nullptr) {}
OpenSSLRSA4096::~OpenSSLRSA4096() { if (keypair_) EVP_PKEY_free(keypair_); }
void OpenSSLRSA4096::generate_keypair() { throw std::runtime_error("Not implemented yet"); }
void OpenSSLRSA4096::sign(const uint8_t*, size_t, uint8_t*, size_t*) { throw std::runtime_error("Not implemented yet"); }
bool OpenSSLRSA4096::verify(const uint8_t*, size_t, const uint8_t*, size_t) { throw std::runtime_error("Not implemented yet"); }

OpenSSLECDSAP256::OpenSSLECDSAP256() : keypair_(nullptr) {}
OpenSSLECDSAP256::~OpenSSLECDSAP256() { if (keypair_) EVP_PKEY_free(keypair_); }
void OpenSSLECDSAP256::generate_keypair() { throw std::runtime_error("Not implemented yet"); }
void OpenSSLECDSAP256::sign(const uint8_t*, size_t, uint8_t*, size_t*) { throw std::runtime_error("Not implemented yet"); }
bool OpenSSLECDSAP256::verify(const uint8_t*, size_t, const uint8_t*, size_t) { throw std::runtime_error("Not implemented yet"); }

OpenSSLEd25519::OpenSSLEd25519() : keypair_(nullptr) {}
OpenSSLEd25519::~OpenSSLEd25519() { if (keypair_) EVP_PKEY_free(keypair_); }
void OpenSSLEd25519::generate_keypair() { throw std::runtime_error("Not implemented yet"); }
void OpenSSLEd25519::sign(const uint8_t*, size_t, uint8_t*, size_t*) { throw std::runtime_error("Not implemented yet"); }
bool OpenSSLEd25519::verify(const uint8_t*, size_t, const uint8_t*, size_t) { throw std::runtime_error("Not implemented yet"); }

// =============================================================================
// Key Exchange Implementations
// =============================================================================

void OpenSSLECDHP256::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    throw std::runtime_error("OpenSSL ECDH-P256 key generation not implemented yet");
}

void OpenSSLECDHP256::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    throw std::runtime_error("OpenSSL ECDH-P256 shared secret computation not implemented yet");
}

void OpenSSLX25519::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    throw std::runtime_error("OpenSSL X25519 key generation not implemented yet");
}

void OpenSSLX25519::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    throw std::runtime_error("OpenSSL X25519 shared secret computation not implemented yet");
}

// =============================================================================
// MAC Implementations
// =============================================================================

void OpenSSLHMACSHA256::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    unsigned int result_len;
    if (!HMAC(EVP_sha256(), key, key_len, message, message_len, mac, &result_len)) {
        throw std::runtime_error("HMAC-SHA256 computation failed");
    }
    if (result_len != mac_len) {
        throw std::runtime_error("HMAC-SHA256 output length mismatch");
    }
}

bool OpenSSLHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    uint8_t computed_mac[32];
    compute(message, message_len, key, key_len, computed_mac, sizeof(computed_mac));
    return CRYPTO_memcmp(computed_mac, mac, mac_len) == 0;
}

void OpenSSLPoly1305::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    throw std::runtime_error("OpenSSL Poly1305 MAC not implemented yet");
}

bool OpenSSLPoly1305::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    throw std::runtime_error("OpenSSL Poly1305 MAC verification not implemented yet");
}

// =============================================================================
// Factory Functions
// =============================================================================

std::unique_ptr<HashAdapter> create_sha256() {
    return std::make_unique<OpenSSLSHA256>();
}

std::unique_ptr<HashAdapter> create_sha512() {
    return std::make_unique<OpenSSLSHA512>();
}

std::unique_ptr<HashAdapter> create_sha3_256() {
    return std::make_unique<OpenSSLSHA3_256>();
}

std::unique_ptr<HashAdapter> create_blake2b() {
    return std::make_unique<OpenSSLBLAKE2b>();
}

std::unique_ptr<SymmetricAdapter> create_aes_128_gcm() {
    return std::make_unique<OpenSSLAES128GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_gcm() {
    return std::make_unique<OpenSSLAES256GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_cbc() {
    return std::make_unique<OpenSSLAES256CBC>();
}

std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305() {
    return std::make_unique<OpenSSLChaCha20Poly1305>();
}

std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048() {
    return std::make_unique<OpenSSLRSA2048>();
}

std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096() {
    return std::make_unique<OpenSSLRSA4096>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256() {
    return std::make_unique<OpenSSLECDSAP256>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ed25519() {
    return std::make_unique<OpenSSLEd25519>();
}

std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256() {
    return std::make_unique<OpenSSLECDHP256>();
}

std::unique_ptr<KeyExchangeAdapter> create_x25519() {
    return std::make_unique<OpenSSLX25519>();
}

std::unique_ptr<MACAdapter> create_hmac_sha256() {
    return std::make_unique<OpenSSLHMACSHA256>();
}

std::unique_ptr<MACAdapter> create_poly1305() {
    return std::make_unique<OpenSSLPoly1305>();
}

} // namespace openssl
} // namespace crypto_bench

#endif // ENABLE_OPENSSL
