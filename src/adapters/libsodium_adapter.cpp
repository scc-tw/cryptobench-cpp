/**
 * libsodium_adapter.cpp - libsodium implementation of crypto_adapter interfaces
 */

#include "libsodium_adapter.h"

#ifdef ENABLE_LIBSODIUM

#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace crypto_bench {
namespace libsodium {

// Initialize libsodium once
static bool libsodium_initialized = false;

static void ensure_libsodium_init() {
    if (!libsodium_initialized) {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }
        libsodium_initialized = true;
    }
}

// =============================================================================
// Hash Function Implementations
// =============================================================================

// SHA-256 implementation
void LibsodiumSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_libsodium_init();
    crypto_hash_sha256(output, data, len);
}

// SHA-512 implementation
void LibsodiumSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_libsodium_init();
    crypto_hash_sha512(output, data, len);
}

// BLAKE2b implementation (512-bit version)
void LibsodiumBLAKE2b::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_libsodium_init();
    crypto_generichash_blake2b(output, 64, data, len, nullptr, 0);
}

// =============================================================================
// Symmetric Encryption Implementations
// =============================================================================

// AES-256-GCM implementation
void LibsodiumAES256GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    ensure_libsodium_init();
    
    // Check if AES-256-GCM is available (requires hardware support)
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM not available on this platform");
    }
    
    if (key_len != crypto_aead_aes256gcm_KEYBYTES) {
        throw std::runtime_error("Invalid key size for AES-256-GCM");
    }
    
    if (iv_len != crypto_aead_aes256gcm_NPUBBYTES) {
        throw std::runtime_error("Invalid IV size for AES-256-GCM");
    }
    
    // libsodium combines ciphertext and tag in output
    std::vector<uint8_t> combined_output(plaintext_len + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertext_len_out;
    
    int ret = crypto_aead_aes256gcm_encrypt(
        combined_output.data(), &ciphertext_len_out,
        plaintext, plaintext_len,
        aad, aad_len,
        nullptr, iv, key
    );
    
    if (ret != 0) {
        throw std::runtime_error("AES-256-GCM encryption failed");
    }
    
    // Split combined output into ciphertext and tag
    std::memcpy(ciphertext, combined_output.data(), plaintext_len);
    std::memcpy(tag, combined_output.data() + plaintext_len, 
                std::min(tag_len, (size_t)crypto_aead_aes256gcm_ABYTES));
}

bool LibsodiumAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    ensure_libsodium_init();
    
    if (!crypto_aead_aes256gcm_is_available()) {
        return false;
    }
    
    if (key_len != crypto_aead_aes256gcm_KEYBYTES || 
        iv_len != crypto_aead_aes256gcm_NPUBBYTES) {
        return false;
    }
    
    // Combine ciphertext and tag for libsodium
    std::vector<uint8_t> combined_input(ciphertext_len + tag_len);
    std::memcpy(combined_input.data(), ciphertext, ciphertext_len);
    std::memcpy(combined_input.data() + ciphertext_len, tag, tag_len);
    
    unsigned long long plaintext_len_out;
    int ret = crypto_aead_aes256gcm_decrypt(
        plaintext, &plaintext_len_out,
        nullptr,
        combined_input.data(), combined_input.size(),
        aad, aad_len,
        iv, key
    );
    
    return ret == 0;
}

// ChaCha20-Poly1305 implementation
void LibsodiumChaCha20Poly1305::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    ensure_libsodium_init();
    
    if (key_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        throw std::runtime_error("Invalid key size for ChaCha20-Poly1305");
    }
    
    if (iv_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        throw std::runtime_error("Invalid IV size for ChaCha20-Poly1305");
    }
    
    // libsodium combines ciphertext and tag in output
    std::vector<uint8_t> combined_output(plaintext_len + crypto_aead_chacha20poly1305_ABYTES);
    unsigned long long ciphertext_len_out;
    
    int ret = crypto_aead_chacha20poly1305_encrypt(
        combined_output.data(), &ciphertext_len_out,
        plaintext, plaintext_len,
        aad, aad_len,
        nullptr, iv, key
    );
    
    if (ret != 0) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }
    
    // Split combined output into ciphertext and tag
    std::memcpy(ciphertext, combined_output.data(), plaintext_len);
    std::memcpy(tag, combined_output.data() + plaintext_len, 
                std::min(tag_len, (size_t)crypto_aead_chacha20poly1305_ABYTES));
}

bool LibsodiumChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    ensure_libsodium_init();
    
    if (key_len != crypto_aead_chacha20poly1305_KEYBYTES || 
        iv_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        return false;
    }
    
    // Combine ciphertext and tag for libsodium
    std::vector<uint8_t> combined_input(ciphertext_len + tag_len);
    std::memcpy(combined_input.data(), ciphertext, ciphertext_len);
    std::memcpy(combined_input.data() + ciphertext_len, tag, tag_len);
    
    unsigned long long plaintext_len_out;
    int ret = crypto_aead_chacha20poly1305_decrypt(
        plaintext, &plaintext_len_out,
        nullptr,
        combined_input.data(), combined_input.size(),
        aad, aad_len,
        iv, key
    );
    
    return ret == 0;
}

// =============================================================================
// Asymmetric Signature Implementations
// =============================================================================

// Ed25519 implementation
LibsodiumEd25519::LibsodiumEd25519() 
    : public_key_(std::make_unique<uint8_t[]>(crypto_sign_PUBLICKEYBYTES)),
      private_key_(std::make_unique<uint8_t[]>(crypto_sign_SECRETKEYBYTES)) {
    ensure_libsodium_init();
}

LibsodiumEd25519::~LibsodiumEd25519() = default;

void LibsodiumEd25519::generate_keypair() {
    crypto_sign_keypair(public_key_.get(), private_key_.get());
}

void LibsodiumEd25519::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    if (*signature_len < crypto_sign_BYTES) {
        *signature_len = crypto_sign_BYTES;
        throw std::runtime_error("Signature buffer too small");
    }
    
    unsigned long long sig_len_out;
    int ret = crypto_sign_detached(signature, &sig_len_out, message, message_len, private_key_.get());
    
    if (ret != 0) {
        throw std::runtime_error("Ed25519 signing failed");
    }
    
    *signature_len = sig_len_out;
}

bool LibsodiumEd25519::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    if (signature_len != crypto_sign_BYTES) {
        return false;
    }
    
    return crypto_sign_verify_detached(signature, message, message_len, public_key_.get()) == 0;
}

// =============================================================================
// Key Exchange Implementations
// =============================================================================

// X25519 implementation
void LibsodiumX25519::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    ensure_libsodium_init();
    
    if (*public_key_len < crypto_box_PUBLICKEYBYTES || 
        *private_key_len < crypto_box_SECRETKEYBYTES) {
        *public_key_len = crypto_box_PUBLICKEYBYTES;
        *private_key_len = crypto_box_SECRETKEYBYTES;
        throw std::runtime_error("Key buffer too small");
    }
    
    crypto_box_keypair(public_key, private_key);
    
    *public_key_len = crypto_box_PUBLICKEYBYTES;
    *private_key_len = crypto_box_SECRETKEYBYTES;
}

void LibsodiumX25519::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    ensure_libsodium_init();
    
    if (our_private_key_len != crypto_box_SECRETKEYBYTES ||
        peer_public_key_len != crypto_box_PUBLICKEYBYTES) {
        throw std::runtime_error("Invalid key sizes for X25519");
    }
    
    if (*shared_secret_len < crypto_box_BEFORENMBYTES) {
        *shared_secret_len = crypto_box_BEFORENMBYTES;
        throw std::runtime_error("Shared secret buffer too small");
    }
    
    int ret = crypto_box_beforenm(shared_secret, peer_public_key, our_private_key);
    if (ret != 0) {
        throw std::runtime_error("X25519 shared secret computation failed");
    }
    
    *shared_secret_len = crypto_box_BEFORENMBYTES;
}

// =============================================================================
// MAC Implementations
// =============================================================================

// HMAC-SHA256 implementation
void LibsodiumHMACSHA256::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    ensure_libsodium_init();
    
    if (mac_len < crypto_auth_hmacsha256_BYTES) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, message, message_len);
    crypto_auth_hmacsha256_final(&state, mac);
}

bool LibsodiumHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    if (mac_len != crypto_auth_hmacsha256_BYTES) {
        return false;
    }
    
    try {
        uint8_t computed_mac[crypto_auth_hmacsha256_BYTES];
        compute(message, message_len, key, key_len, computed_mac, sizeof(computed_mac));
        
        return crypto_verify_32(mac, computed_mac) == 0;
    } catch (...) {
        return false;
    }
}

// HMAC-SHA512 implementation
void LibsodiumHMACSHA512::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    ensure_libsodium_init();
    
    if (mac_len < crypto_auth_hmacsha512_BYTES) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    crypto_auth_hmacsha512_state state;
    crypto_auth_hmacsha512_init(&state, key, key_len);
    crypto_auth_hmacsha512_update(&state, message, message_len);
    crypto_auth_hmacsha512_final(&state, mac);
}

bool LibsodiumHMACSHA512::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    if (mac_len != crypto_auth_hmacsha512_BYTES) {
        return false;
    }
    
    try {
        uint8_t computed_mac[crypto_auth_hmacsha512_BYTES];
        compute(message, message_len, key, key_len, computed_mac, sizeof(computed_mac));
        
        return crypto_verify_64(mac, computed_mac) == 0;
    } catch (...) {
        return false;
    }
}

// Poly1305 implementation
void LibsodiumPoly1305::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    ensure_libsodium_init();
    
    if (key_len != crypto_onetimeauth_poly1305_KEYBYTES) {
        throw std::runtime_error("Invalid key size for Poly1305");
    }
    
    if (mac_len < crypto_onetimeauth_poly1305_BYTES) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    crypto_onetimeauth_poly1305(mac, message, message_len, key);
}

bool LibsodiumPoly1305::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    if (key_len != crypto_onetimeauth_poly1305_KEYBYTES ||
        mac_len != crypto_onetimeauth_poly1305_BYTES) {
        return false;
    }
    
    return crypto_onetimeauth_poly1305_verify(mac, message, message_len, key) == 0;
}

// =============================================================================
// Factory Functions
// =============================================================================

// Hash function factory functions
std::unique_ptr<HashAdapter> create_sha256() {
    return std::make_unique<LibsodiumSHA256>();
}

std::unique_ptr<HashAdapter> create_sha512() {
    return std::make_unique<LibsodiumSHA512>();
}

std::unique_ptr<HashAdapter> create_blake2b() {
    return std::make_unique<LibsodiumBLAKE2b>();
}

// Symmetric encryption factory functions
std::unique_ptr<SymmetricAdapter> create_aes_256_gcm() {
    return std::make_unique<LibsodiumAES256GCM>();
}

std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305() {
    return std::make_unique<LibsodiumChaCha20Poly1305>();
}

// Asymmetric signature factory functions
std::unique_ptr<AsymmetricSignAdapter> create_ed25519() {
    return std::make_unique<LibsodiumEd25519>();
}

// Key exchange factory functions
std::unique_ptr<KeyExchangeAdapter> create_x25519() {
    return std::make_unique<LibsodiumX25519>();
}

// MAC factory functions
std::unique_ptr<MACAdapter> create_hmac_sha256() {
    return std::make_unique<LibsodiumHMACSHA256>();
}

std::unique_ptr<MACAdapter> create_hmac_sha512() {
    return std::make_unique<LibsodiumHMACSHA512>();
}

std::unique_ptr<MACAdapter> create_poly1305() {
    return std::make_unique<LibsodiumPoly1305>();
}

} // namespace libsodium
} // namespace crypto_bench

#endif // ENABLE_LIBSODIUM
