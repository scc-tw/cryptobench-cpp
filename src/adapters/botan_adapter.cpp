/**
 * botan_adapter.cpp - Botan implementation of crypto_adapter interfaces
 */

#include "botan_adapter.h"

#ifdef ENABLE_BOTAN

#include <botan/hash.h>
// Advanced features
#include <botan/cipher_mode.h>
#include <botan/aead.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/ecdh.h>
#include <botan/curve25519.h>
#include <botan/ec_group.h>
#include <botan/rng.h>
#include <botan/system_rng.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <cstring>

namespace crypto_bench {
namespace botan {

// Helper function to get RNG
static Botan::RandomNumberGenerator& get_rng() {
    static Botan::System_RNG rng;
    return rng;
}

//=============================================================================
// Hash Functions
//=============================================================================

// SHA-256 implementation
void BotanSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    auto hasher = Botan::HashFunction::create("SHA-256");
    if (!hasher) {
        throw std::runtime_error("SHA-256 not available in Botan");
    }
    hasher->update(data, len);
    hasher->final(output);
}

// SHA-512 implementation
void BotanSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    auto hasher = Botan::HashFunction::create("SHA-512");
    if (!hasher) {
        throw std::runtime_error("SHA-512 not available in Botan");
    }
    hasher->update(data, len);
    hasher->final(output);
}

// SHA3-256 implementation
void BotanSHA3_256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    auto hasher = Botan::HashFunction::create("SHA-3(256)");
    if (!hasher) {
        throw std::runtime_error("SHA3-256 not available in Botan");
    }
    hasher->update(data, len);
    hasher->final(output);
}

// BLAKE2b implementation (512-bit version)
void BotanBLAKE2b::hash(const uint8_t* data, size_t len, uint8_t* output) {
    auto hasher = Botan::HashFunction::create("BLAKE2b(512)");
    if (!hasher) {
        throw std::runtime_error("BLAKE2b not available in Botan");
    }
    hasher->update(data, len);
    hasher->final(output);
}

//=============================================================================
// Symmetric Encryption
//=============================================================================

// AES-128-GCM implementation
void BotanAES128GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len) {
    
    auto aead = Botan::AEAD_Mode::create("AES-128/GCM", Botan::ENCRYPTION);
    if (!aead) {
        throw std::runtime_error("AES-128-GCM not available in Botan");
    }
    
    aead->set_key(key, key_len);
    aead->start(iv, iv_len);
    
    if (aad && aad_len > 0) {
        aead->set_associated_data(aad, aad_len);
    }
    
    Botan::secure_vector<uint8_t> buffer(plaintext, plaintext + plaintext_len);
    aead->finish(buffer);
    
    // Copy ciphertext and tag
    std::memcpy(ciphertext, buffer.data(), plaintext_len);
    std::memcpy(tag, buffer.data() + plaintext_len, tag_len);
}

bool BotanAES128GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext) {
    
    try {
        auto aead = Botan::AEAD_Mode::create("AES-128/GCM", Botan::DECRYPTION);
        if (!aead) {
            return false;
        }
        
        aead->set_key(key, key_len);
        aead->start(iv, iv_len);
        
        if (aad && aad_len > 0) {
            aead->set_associated_data(aad, aad_len);
        }
        
        Botan::secure_vector<uint8_t> buffer(ciphertext_len + tag_len);
        std::memcpy(buffer.data(), ciphertext, ciphertext_len);
        std::memcpy(buffer.data() + ciphertext_len, tag, tag_len);
        
        aead->finish(buffer);
        std::memcpy(plaintext, buffer.data(), ciphertext_len);
        return true;
    } catch (...) {
        return false;
    }
}

// AES-256-GCM implementation
void BotanAES256GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len) {
    
    auto aead = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
    if (!aead) {
        throw std::runtime_error("AES-256-GCM not available in Botan");
    }
    
    aead->set_key(key, key_len);
    aead->start(iv, iv_len);
    
    if (aad && aad_len > 0) {
        aead->set_associated_data(aad, aad_len);
    }
    
    Botan::secure_vector<uint8_t> buffer(plaintext, plaintext + plaintext_len);
    aead->finish(buffer);
    
    // Copy ciphertext and tag
    std::memcpy(ciphertext, buffer.data(), plaintext_len);
    std::memcpy(tag, buffer.data() + plaintext_len, tag_len);
}

bool BotanAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext) {
    
    try {
        auto aead = Botan::AEAD_Mode::create("AES-256/GCM", Botan::DECRYPTION);
        if (!aead) {
            return false;
        }
        
        aead->set_key(key, key_len);
        aead->start(iv, iv_len);
        
        if (aad && aad_len > 0) {
            aead->set_associated_data(aad, aad_len);
        }
        
        Botan::secure_vector<uint8_t> buffer(ciphertext_len + tag_len);
        std::memcpy(buffer.data(), ciphertext, ciphertext_len);
        std::memcpy(buffer.data() + ciphertext_len, tag, tag_len);
        
        aead->finish(buffer);
        std::memcpy(plaintext, buffer.data(), ciphertext_len);
        return true;
    } catch (...) {
        return false;
    }
}

// AES-256-CBC implementation
void BotanAES256CBC::encrypt_cbc(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* ciphertext) {
    
    auto cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::ENCRYPTION);
    if (!cipher) {
        throw std::runtime_error("AES-256-CBC not available in Botan");
    }
    
    cipher->set_key(key, key_len);
    cipher->start(iv, iv_len);
    
    Botan::secure_vector<uint8_t> buffer(plaintext, plaintext + plaintext_len);
    cipher->finish(buffer);
    
    std::memcpy(ciphertext, buffer.data(), buffer.size());
}

void BotanAES256CBC::decrypt_cbc(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext) {
    
    auto cipher = Botan::Cipher_Mode::create("AES-256/CBC/PKCS7", Botan::DECRYPTION);
    if (!cipher) {
        throw std::runtime_error("AES-256-CBC not available in Botan");
    }
    
    cipher->set_key(key, key_len);
    cipher->start(iv, iv_len);
    
    Botan::secure_vector<uint8_t> buffer(ciphertext, ciphertext + ciphertext_len);
    cipher->finish(buffer);
    
    std::memcpy(plaintext, buffer.data(), buffer.size());
}

// ChaCha20-Poly1305 implementation
void BotanChaCha20Poly1305::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len) {
    
    auto aead = Botan::AEAD_Mode::create("ChaCha20Poly1305", Botan::ENCRYPTION);
    if (!aead) {
        throw std::runtime_error("ChaCha20-Poly1305 not available in Botan");
    }
    
    aead->set_key(key, key_len);
    aead->start(iv, iv_len);
    
    if (aad && aad_len > 0) {
        aead->set_associated_data(aad, aad_len);
    }
    
    Botan::secure_vector<uint8_t> buffer(plaintext, plaintext + plaintext_len);
    aead->finish(buffer);
    
    // Copy ciphertext and tag
    std::memcpy(ciphertext, buffer.data(), plaintext_len);
    std::memcpy(tag, buffer.data() + plaintext_len, tag_len);
}

bool BotanChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext) {
    
    try {
        auto aead = Botan::AEAD_Mode::create("ChaCha20Poly1305", Botan::DECRYPTION);
        if (!aead) {
            return false;
        }
        
        aead->set_key(key, key_len);
        aead->start(iv, iv_len);
        
        if (aad && aad_len > 0) {
            aead->set_associated_data(aad, aad_len);
        }
        
        Botan::secure_vector<uint8_t> buffer(ciphertext_len + tag_len);
        std::memcpy(buffer.data(), ciphertext, ciphertext_len);
        std::memcpy(buffer.data() + ciphertext_len, tag, tag_len);
        
        aead->finish(buffer);
        std::memcpy(plaintext, buffer.data(), ciphertext_len);
        return true;
    } catch (...) {
        return false;
    }
}

//=============================================================================
// Asymmetric Signatures
//=============================================================================

// RSA-2048 implementation
BotanRSA2048::BotanRSA2048() : private_key_(nullptr), public_key_(nullptr) {}

BotanRSA2048::~BotanRSA2048() {
    if (private_key_) {
        delete static_cast<Botan::RSA_PrivateKey*>(private_key_.release());
    }
    if (public_key_) {
        delete static_cast<Botan::RSA_PublicKey*>(public_key_.release());
    }
}

void BotanRSA2048::generate_keypair() {
    auto priv_key = std::make_unique<Botan::RSA_PrivateKey>(get_rng(), 2048);
    auto pub_key = std::make_unique<Botan::RSA_PublicKey>(*priv_key);
    
    private_key_.reset(priv_key.release());
    public_key_.reset(pub_key.release());
}

void BotanRSA2048::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len) {
    
    if (!private_key_) {
        throw std::runtime_error("Private key not generated");
    }
    
    auto signer = Botan::PK_Signer(*static_cast<Botan::RSA_PrivateKey*>(private_key_.get()), 
                                   get_rng(), "EMSA-PSS(SHA-256)");
    
    auto sig = signer.sign_message(message, message_len, get_rng());
    
    if (sig.size() > *signature_len) {
        *signature_len = sig.size();
        throw std::runtime_error("Signature buffer too small");
    }
    
    std::memcpy(signature, sig.data(), sig.size());
    *signature_len = sig.size();
}

bool BotanRSA2048::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len) {
    
    if (!public_key_) {
        return false;
    }
    
    try {
        auto verifier = Botan::PK_Verifier(*static_cast<Botan::RSA_PublicKey*>(public_key_.get()), 
                                          "EMSA-PSS(SHA-256)");
        return verifier.verify_message(message, message_len, signature, signature_len);
    } catch (...) {
        return false;
    }
}

// RSA-4096 implementation
BotanRSA4096::BotanRSA4096() : private_key_(nullptr), public_key_(nullptr) {}

BotanRSA4096::~BotanRSA4096() {
    if (private_key_) {
        delete static_cast<Botan::RSA_PrivateKey*>(private_key_.release());
    }
    if (public_key_) {
        delete static_cast<Botan::RSA_PublicKey*>(public_key_.release());
    }
}

void BotanRSA4096::generate_keypair() {
    auto priv_key = std::make_unique<Botan::RSA_PrivateKey>(get_rng(), 4096);
    auto pub_key = std::make_unique<Botan::RSA_PublicKey>(*priv_key);
    
    private_key_.reset(priv_key.release());
    public_key_.reset(pub_key.release());
}

void BotanRSA4096::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len) {
    
    if (!private_key_) {
        throw std::runtime_error("Private key not generated");
    }
    
    auto signer = Botan::PK_Signer(*static_cast<Botan::RSA_PrivateKey*>(private_key_.get()), 
                                   get_rng(), "EMSA-PSS(SHA-256)");
    
    auto sig = signer.sign_message(message, message_len, get_rng());
    
    if (sig.size() > *signature_len) {
        *signature_len = sig.size();
        throw std::runtime_error("Signature buffer too small");
    }
    
    std::memcpy(signature, sig.data(), sig.size());
    *signature_len = sig.size();
}

bool BotanRSA4096::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len) {
    
    if (!public_key_) {
        return false;
    }
    
    try {
        auto verifier = Botan::PK_Verifier(*static_cast<Botan::RSA_PublicKey*>(public_key_.get()), 
                                          "EMSA-PSS(SHA-256)");
        return verifier.verify_message(message, message_len, signature, signature_len);
    } catch (...) {
        return false;
    }
}

// ECDSA-P256 implementation
BotanECDSAP256::BotanECDSAP256() : private_key_(nullptr), public_key_(nullptr) {}

BotanECDSAP256::~BotanECDSAP256() {
    if (private_key_) {
        delete static_cast<Botan::ECDSA_PrivateKey*>(private_key_.release());
    }
    if (public_key_) {
        delete static_cast<Botan::ECDSA_PublicKey*>(public_key_.release());
    }
}

void BotanECDSAP256::generate_keypair() {
    auto group = Botan::EC_Group("secp256r1");
    auto priv_key = std::make_unique<Botan::ECDSA_PrivateKey>(get_rng(), group);
    auto pub_key = std::make_unique<Botan::ECDSA_PublicKey>(*priv_key);
    
    private_key_.reset(priv_key.release());
    public_key_.reset(pub_key.release());
}

void BotanECDSAP256::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len) {
    
    if (!private_key_) {
        throw std::runtime_error("Private key not generated");
    }
    
    auto signer = Botan::PK_Signer(*static_cast<Botan::ECDSA_PrivateKey*>(private_key_.get()), 
                                   get_rng(), "EMSA1(SHA-256)");
    
    auto sig = signer.sign_message(message, message_len, get_rng());
    
    if (sig.size() > *signature_len) {
        *signature_len = sig.size();
        throw std::runtime_error("Signature buffer too small");
    }
    
    std::memcpy(signature, sig.data(), sig.size());
    *signature_len = sig.size();
}

bool BotanECDSAP256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len) {
    
    if (!public_key_) {
        return false;
    }
    
    try {
        auto verifier = Botan::PK_Verifier(*static_cast<Botan::ECDSA_PublicKey*>(public_key_.get()), 
                                          "EMSA1(SHA-256)");
        return verifier.verify_message(message, message_len, signature, signature_len);
    } catch (...) {
        return false;
    }
}

// Ed25519 implementation
BotanEd25519::BotanEd25519() : private_key_(nullptr), public_key_(nullptr) {}

BotanEd25519::~BotanEd25519() {
    if (private_key_) {
        delete static_cast<Botan::Ed25519_PrivateKey*>(private_key_.release());
    }
    if (public_key_) {
        delete static_cast<Botan::Ed25519_PublicKey*>(public_key_.release());
    }
}

void BotanEd25519::generate_keypair() {
    auto priv_key = std::make_unique<Botan::Ed25519_PrivateKey>(get_rng());
    auto pub_key = std::make_unique<Botan::Ed25519_PublicKey>(*priv_key);
    
    private_key_.reset(priv_key.release());
    public_key_.reset(pub_key.release());
}

void BotanEd25519::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len) {
    
    if (!private_key_) {
        throw std::runtime_error("Private key not generated");
    }
    
    auto signer = Botan::PK_Signer(*static_cast<Botan::Ed25519_PrivateKey*>(private_key_.get()), 
                                   get_rng(), "Pure");
    
    auto sig = signer.sign_message(message, message_len, get_rng());
    
    if (sig.size() > *signature_len) {
        *signature_len = sig.size();
        throw std::runtime_error("Signature buffer too small");
    }
    
    std::memcpy(signature, sig.data(), sig.size());
    *signature_len = sig.size();
}

bool BotanEd25519::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len) {
    
    if (!public_key_) {
        return false;
    }
    
    try {
        auto verifier = Botan::PK_Verifier(*static_cast<Botan::Ed25519_PublicKey*>(public_key_.get()), 
                                          "Pure");
        return verifier.verify_message(message, message_len, signature, signature_len);
    } catch (...) {
        return false;
    }
}

//=============================================================================
// Key Exchange
//=============================================================================

// ECDH-P256 implementation
void BotanECDHP256::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len) {
    
    auto group = Botan::EC_Group("secp256r1");
    auto priv_key = Botan::ECDH_PrivateKey(get_rng(), group);
    
    // Get private key bytes
    auto priv_bytes = priv_key.private_value_bytes();
    if (priv_bytes.size() > *private_key_len) {
        *private_key_len = priv_bytes.size();
        throw std::runtime_error("Private key buffer too small");
    }
    std::memcpy(private_key, priv_bytes.data(), priv_bytes.size());
    *private_key_len = priv_bytes.size();
    
    // Get public key bytes (uncompressed)
    auto pub_bytes = priv_key.public_key_bits();
    if (pub_bytes.size() > *public_key_len) {
        *public_key_len = pub_bytes.size();
        throw std::runtime_error("Public key buffer too small");
    }
    std::memcpy(public_key, pub_bytes.data(), pub_bytes.size());
    *public_key_len = pub_bytes.size();
}

void BotanECDHP256::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len) {
    
    try {
        auto group = Botan::EC_Group("secp256r1");
        
        // Reconstruct our private key
        Botan::BigInt priv_scalar(our_private_key, our_private_key_len);
        auto our_priv_key = Botan::ECDH_PrivateKey(get_rng(), group, priv_scalar);
        
        // Reconstruct peer public key
        auto peer_pub_key = Botan::ECDH_PublicKey(group, group.point(peer_public_key, peer_public_key_len));
        
        // Perform key agreement
        auto ka = Botan::PK_Key_Agreement(our_priv_key, get_rng(), "Raw");
        auto secret = ka.derive_key(*shared_secret_len, peer_pub_key.public_key_bits()).bits_of();
        
        if (secret.size() > *shared_secret_len) {
            *shared_secret_len = secret.size();
            throw std::runtime_error("Shared secret buffer too small");
        }
        
        std::memcpy(shared_secret, secret.data(), secret.size());
        *shared_secret_len = secret.size();
    } catch (const std::exception& e) {
        throw std::runtime_error("ECDH key agreement failed: " + std::string(e.what()));
    }
}

// X25519 implementation
void BotanX25519::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len) {
    
    auto priv_key = Botan::Curve25519_PrivateKey(get_rng());
    
    // Get private key bytes
    auto priv_bytes = priv_key.private_key_bits();
    if (priv_bytes.size() > *private_key_len) {
        *private_key_len = priv_bytes.size();
        throw std::runtime_error("Private key buffer too small");
    }
    std::memcpy(private_key, priv_bytes.data(), priv_bytes.size());
    *private_key_len = priv_bytes.size();
    
    // Get public key bytes
    auto pub_bytes = priv_key.public_key_bits();
    if (pub_bytes.size() > *public_key_len) {
        *public_key_len = pub_bytes.size();
        throw std::runtime_error("Public key buffer too small");
    }
    std::memcpy(public_key, pub_bytes.data(), pub_bytes.size());
    *public_key_len = pub_bytes.size();
}

void BotanX25519::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len) {
    
    try {
        // Reconstruct our private key
        auto our_priv_key = Botan::Curve25519_PrivateKey(
            Botan::secure_vector<uint8_t>(our_private_key, our_private_key + our_private_key_len));
        
        // Reconstruct peer public key
        auto peer_pub_key = Botan::Curve25519_PublicKey(
            std::vector<uint8_t>(peer_public_key, peer_public_key + peer_public_key_len));
        
        // Perform key agreement
        auto ka = Botan::PK_Key_Agreement(our_priv_key, get_rng(), "Raw");
        auto secret = ka.derive_key(*shared_secret_len, peer_pub_key.public_key_bits()).bits_of();
        
        if (secret.size() > *shared_secret_len) {
            *shared_secret_len = secret.size();
            throw std::runtime_error("Shared secret buffer too small");
        }
        
        std::memcpy(shared_secret, secret.data(), secret.size());
        *shared_secret_len = secret.size();
    } catch (const std::exception& e) {
        throw std::runtime_error("X25519 key agreement failed: " + std::string(e.what()));
    }
}

//=============================================================================
// Message Authentication Codes
//=============================================================================

// HMAC-SHA256 implementation
void BotanHMACSHA256::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len) {
    
    auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    if (!hmac) {
        throw std::runtime_error("HMAC-SHA256 not available in Botan");
    }
    
    hmac->set_key(key, key_len);
    hmac->update(message, message_len);
    
    auto result = hmac->final();
    if (result.size() > mac_len) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    std::memcpy(mac, result.data(), result.size());
}

bool BotanHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len) {
    
    try {
        auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
        if (!hmac) {
            return false;
        }
        
        hmac->set_key(key, key_len);
        hmac->update(message, message_len);
        
        auto computed = hmac->final();
        
        if (computed.size() != mac_len) {
            return false;
        }
        
        return std::memcmp(computed.data(), mac, mac_len) == 0;
    } catch (...) {
        return false;
    }
}

// Poly1305 implementation
void BotanPoly1305::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len) {
    
    auto poly = Botan::MessageAuthenticationCode::create("Poly1305");
    if (!poly) {
        throw std::runtime_error("Poly1305 not available in Botan");
    }
    
    poly->set_key(key, key_len);
    poly->update(message, message_len);
    
    auto result = poly->final();
    if (result.size() > mac_len) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    std::memcpy(mac, result.data(), result.size());
}

bool BotanPoly1305::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len) {
    
    try {
        auto poly = Botan::MessageAuthenticationCode::create("Poly1305");
        if (!poly) {
            return false;
        }
        
        poly->set_key(key, key_len);
        poly->update(message, message_len);
        
        auto computed = poly->final();
        
        if (computed.size() != mac_len) {
            return false;
        }
        
        return std::memcmp(computed.data(), mac, mac_len) == 0;
    } catch (...) {
        return false;
    }
}

//=============================================================================
// Factory Functions
//=============================================================================

// Hash functions
std::unique_ptr<HashAdapter> create_sha256() {
    return std::make_unique<BotanSHA256>();
}

std::unique_ptr<HashAdapter> create_sha512() {
    return std::make_unique<BotanSHA512>();
}

std::unique_ptr<HashAdapter> create_sha3_256() {
    return std::make_unique<BotanSHA3_256>();
}

std::unique_ptr<HashAdapter> create_blake2b() {
    return std::make_unique<BotanBLAKE2b>();
}

// Symmetric encryption
std::unique_ptr<SymmetricAdapter> create_aes_128_gcm() {
    return std::make_unique<BotanAES128GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_gcm() {
    return std::make_unique<BotanAES256GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_cbc() {
    return std::make_unique<BotanAES256CBC>();
}

std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305() {
    return std::make_unique<BotanChaCha20Poly1305>();
}

// Asymmetric signatures
std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048() {
    return std::make_unique<BotanRSA2048>();
}

std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096() {
    return std::make_unique<BotanRSA4096>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256() {
    return std::make_unique<BotanECDSAP256>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ed25519() {
    return std::make_unique<BotanEd25519>();
}

// Key exchange
std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256() {
    return std::make_unique<BotanECDHP256>();
}

std::unique_ptr<KeyExchangeAdapter> create_x25519() {
    return std::make_unique<BotanX25519>();
}

// MAC
std::unique_ptr<MACAdapter> create_hmac_sha256() {
    return std::make_unique<BotanHMACSHA256>();
}

std::unique_ptr<MACAdapter> create_poly1305() {
    return std::make_unique<BotanPoly1305>();
}

} // namespace botan
} // namespace crypto_bench

#endif // ENABLE_BOTAN