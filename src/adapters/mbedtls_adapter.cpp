/**
 * mbedtls_adapter.cpp - mbedTLS implementation of crypto_adapter interfaces
 */

#include "mbedtls_adapter.h"

#ifdef ENABLE_MBEDTLS

// MbedTLS 4.0 - Using PSA Crypto API
#include <psa/crypto.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <stdexcept>
#include <cstring>
#include <vector>

namespace crypto_bench {
namespace mbedtls {

// PSA Crypto initialization helper
static bool psa_initialized = false;

static void ensure_psa_initialized() {
    if (!psa_initialized) {
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("PSA Crypto initialization failed");
        }
        psa_initialized = true;
    }
}

// SHA-256 implementation
void MbedTLSSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_psa_initialized();
    
    size_t output_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, data, len, output, 32, &output_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("SHA-256 computation failed");
    }
}

// SHA-512 implementation
void MbedTLSSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_psa_initialized();
    
    size_t output_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_512, data, len, output, 64, &output_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("SHA-512 computation failed");
    }
}

// SHA3-256 implementation
void MbedTLSSHA3_256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    ensure_psa_initialized();
    
    size_t output_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA3_256, data, len, output, 32, &output_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("SHA3-256 computation failed");
    }
}

// Factory functions
std::unique_ptr<HashAdapter> create_sha256() {
    return std::make_unique<MbedTLSSHA256>();
}

std::unique_ptr<HashAdapter> create_sha512() {
    return std::make_unique<MbedTLSSHA512>();
}

std::unique_ptr<HashAdapter> create_sha3_256() {
    return std::make_unique<MbedTLSSHA3_256>();
}

// =============================================================================
// Symmetric Encryption Implementations
// =============================================================================

// AES-128-GCM implementation
void MbedTLSAES128GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("AES-128-GCM key import failed");
    }
    
    try {
        // PSA AEAD encrypt writes ciphertext+tag to a single buffer
        std::vector<uint8_t> output_buffer(plaintext_len + tag_len);
        size_t output_length;
        status = psa_aead_encrypt(key_id, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
            plaintext, plaintext_len, output_buffer.data(), output_buffer.size(), &output_length);
        
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("AES-128-GCM encryption failed");
        }
        
        // Separate ciphertext and tag
        memcpy(ciphertext, output_buffer.data(), plaintext_len);
        memcpy(tag, output_buffer.data() + plaintext_len, tag_len);
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

bool MbedTLSAES128GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    try {
        // Create combined ciphertext+tag buffer for PSA API
        std::vector<uint8_t> combined_input(ciphertext_len + tag_len);
        memcpy(combined_input.data(), ciphertext, ciphertext_len);
        memcpy(combined_input.data() + ciphertext_len, tag, tag_len);
        
        size_t output_length;
        status = psa_aead_decrypt(key_id, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
            combined_input.data(), combined_input.size(), plaintext, ciphertext_len, &output_length);
        
        psa_destroy_key(key_id);
        return status == PSA_SUCCESS;
    } catch (...) {
        psa_destroy_key(key_id);
        return false;
    }
}

// AES-256-GCM implementation
void MbedTLSAES256GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("AES-256-GCM key import failed");
    }
    
    try {
        // PSA AEAD encrypt writes ciphertext+tag to a single buffer
        std::vector<uint8_t> output_buffer(plaintext_len + tag_len);
        size_t output_length;
        status = psa_aead_encrypt(key_id, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
            plaintext, plaintext_len, output_buffer.data(), output_buffer.size(), &output_length);
        
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("AES-256-GCM encryption failed");
        }
        
        // Separate ciphertext and tag
        memcpy(ciphertext, output_buffer.data(), plaintext_len);
        memcpy(tag, output_buffer.data() + plaintext_len, tag_len);
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

bool MbedTLSAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    try {
        // Create combined ciphertext+tag buffer for PSA API
        std::vector<uint8_t> combined_input(ciphertext_len + tag_len);
        memcpy(combined_input.data(), ciphertext, ciphertext_len);
        memcpy(combined_input.data() + ciphertext_len, tag, tag_len);
        
        size_t output_length;
        status = psa_aead_decrypt(key_id, PSA_ALG_GCM, iv, iv_len, aad, aad_len,
            combined_input.data(), combined_input.size(), plaintext, ciphertext_len, &output_length);
        
        psa_destroy_key(key_id);
        return status == PSA_SUCCESS;
    } catch (...) {
        psa_destroy_key(key_id);
        return false;
    }
}

// AES-256-CBC implementation
void MbedTLSAES256CBC::encrypt_cbc(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* ciphertext
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("AES-256-CBC key import failed");
    }
    
    try {
        psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
        status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING);
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("AES-256-CBC encrypt setup failed");
        }
        
        status = psa_cipher_set_iv(&operation, iv, iv_len);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            throw std::runtime_error("AES-256-CBC IV setup failed");
        }
        
        size_t output_length = 0;
        status = psa_cipher_update(&operation, plaintext, plaintext_len,
            ciphertext, plaintext_len, &output_length);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            throw std::runtime_error("AES-256-CBC encryption failed");
        }
        
        uint8_t finish_buf[16];
        size_t final_length = 0;
        status = psa_cipher_finish(&operation, finish_buf, sizeof(finish_buf), &final_length);
        if (status != PSA_SUCCESS || final_length != 0) {
            throw std::runtime_error("AES-256-CBC encryption finish failed");
        }
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

void MbedTLSAES256CBC::decrypt_cbc(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("AES-256-CBC key import failed");
    }
    
    try {
        psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
        status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING);
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("AES-256-CBC decrypt setup failed");
        }
        
        status = psa_cipher_set_iv(&operation, iv, iv_len);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            throw std::runtime_error("AES-256-CBC IV setup failed");
        }
        
        size_t output_length = 0;
        status = psa_cipher_update(&operation, ciphertext, ciphertext_len,
            plaintext, ciphertext_len, &output_length);
        if (status != PSA_SUCCESS) {
            psa_cipher_abort(&operation);
            throw std::runtime_error("AES-256-CBC decryption failed");
        }
        
        uint8_t finish_buf[16];
        size_t final_length = 0;
        status = psa_cipher_finish(&operation, finish_buf, sizeof(finish_buf), &final_length);
        if (status != PSA_SUCCESS || final_length != 0) {
            throw std::runtime_error("AES-256-CBC decryption finish failed");
        }
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

// ChaCha20-Poly1305 implementation
void MbedTLSChaCha20Poly1305::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attributes, 256);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ChaCha20-Poly1305 key import failed");
    }
    
    try {
        // PSA AEAD encrypt writes ciphertext+tag to a single buffer
        std::vector<uint8_t> output_buffer(plaintext_len + tag_len);
        size_t output_length;
        status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305, iv, iv_len, aad, aad_len,
            plaintext, plaintext_len, output_buffer.data(), output_buffer.size(), &output_length);
        
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
        }
        
        // Separate ciphertext and tag
        memcpy(ciphertext, output_buffer.data(), plaintext_len);
        memcpy(tag, output_buffer.data() + plaintext_len, tag_len);
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

bool MbedTLSChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    ensure_psa_initialized();
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
    psa_set_key_bits(&attributes, 256);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    try {
        // Create combined ciphertext+tag buffer for PSA API
        std::vector<uint8_t> combined_input(ciphertext_len + tag_len);
        memcpy(combined_input.data(), ciphertext, ciphertext_len);
        memcpy(combined_input.data() + ciphertext_len, tag, tag_len);
        
        size_t output_length;
        status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305, iv, iv_len, aad, aad_len,
            combined_input.data(), combined_input.size(), plaintext, ciphertext_len, &output_length);
        
        psa_destroy_key(key_id);
        return status == PSA_SUCCESS;
    } catch (...) {
        psa_destroy_key(key_id);
        return false;
    }
}

// =============================================================================
// Asymmetric Signature Implementations
// =============================================================================

// RSA-2048 implementation
MbedTLSRSA2048::MbedTLSRSA2048() : key_id_(0) {
    ensure_psa_initialized();
}

MbedTLSRSA2048::~MbedTLSRSA2048() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
    }
}

void MbedTLSRSA2048::generate_keypair() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
        key_id_ = 0;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, 2048);
    
    psa_status_t status = psa_generate_key(&attributes, &key_id_);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-2048 key generation failed");
    }
}

void MbedTLSRSA2048::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    if (key_id_ == 0) {
        throw std::runtime_error("RSA-2048 key not generated");
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-2048 hash computation failed");
    }
    
    // Sign the hash
    status = psa_sign_hash(key_id_, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), 
        hash, hash_len, signature, signature_size(), signature_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-2048 signing failed");
    }
}

bool MbedTLSRSA2048::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    if (key_id_ == 0) {
        return false;
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    // Verify the signature
    status = psa_verify_hash(key_id_, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), 
        hash, hash_len, signature, signature_len);
    return status == PSA_SUCCESS;
}

// RSA-4096 implementation
MbedTLSRSA4096::MbedTLSRSA4096() : key_id_(0) {
    ensure_psa_initialized();
}

MbedTLSRSA4096::~MbedTLSRSA4096() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
    }
}

void MbedTLSRSA4096::generate_keypair() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
        key_id_ = 0;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, 4096);
    
    psa_status_t status = psa_generate_key(&attributes, &key_id_);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-4096 key generation failed");
    }
}

void MbedTLSRSA4096::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    if (key_id_ == 0) {
        throw std::runtime_error("RSA-4096 key not generated");
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-4096 hash computation failed");
    }
    
    // Sign the hash
    status = psa_sign_hash(key_id_, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), 
        hash, hash_len, signature, signature_size(), signature_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("RSA-4096 signing failed");
    }
}

bool MbedTLSRSA4096::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    if (key_id_ == 0) {
        return false;
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    // Verify the signature
    status = psa_verify_hash(key_id_, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), 
        hash, hash_len, signature, signature_len);
    return status == PSA_SUCCESS;
}

// ECDSA-P256 implementation
MbedTLSECDSAP256::MbedTLSECDSAP256() : key_id_(0) {
    ensure_psa_initialized();
}

MbedTLSECDSAP256::~MbedTLSECDSAP256() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
    }
}

void MbedTLSECDSAP256::generate_keypair() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
        key_id_ = 0;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    
    psa_status_t status = psa_generate_key(&attributes, &key_id_);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDSA-P256 key generation failed");
    }
}

void MbedTLSECDSAP256::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    if (key_id_ == 0) {
        throw std::runtime_error("ECDSA-P256 key not generated");
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDSA-P256 hash computation failed");
    }
    
    // Sign the hash
    status = psa_sign_hash(key_id_, PSA_ALG_ECDSA(PSA_ALG_SHA_256), 
        hash, hash_len, signature, 72, signature_len); // ECDSA P-256 max signature is ~72 bytes
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDSA-P256 signing failed");
    }
}

bool MbedTLSECDSAP256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    if (key_id_ == 0) {
        return false;
    }
    
    // Hash the message
    unsigned char hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, message, message_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    // Verify the signature
    status = psa_verify_hash(key_id_, PSA_ALG_ECDSA(PSA_ALG_SHA_256), 
        hash, hash_len, signature, signature_len);
    return status == PSA_SUCCESS;
}

// =============================================================================
// Key Exchange Implementations
// =============================================================================

// ECDH-P256 implementation
MbedTLSECDHP256::MbedTLSECDHP256() : key_id_(0) {
    ensure_psa_initialized();
}

MbedTLSECDHP256::~MbedTLSECDHP256() {
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
    }
}

void MbedTLSECDHP256::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    if (*public_key_len < public_key_size()) {
        *public_key_len = public_key_size();
        *private_key_len = 0; // PSA doesn't export private keys directly
        throw std::runtime_error("Key buffer too small");
    }
    
    if (key_id_ != 0) {
        psa_destroy_key(key_id_);
        key_id_ = 0;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    
    psa_status_t status = psa_generate_key(&attributes, &key_id_);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDH-P256 key generation failed");
    }
    
    // Export public key
    status = psa_export_public_key(key_id_, public_key, public_key_size(), public_key_len);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDH-P256 public key export failed");
    }
    
    // PSA doesn't allow exporting private keys for ECDH, so we set this to 0
    *private_key_len = 0;
}

void MbedTLSECDHP256::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    if (*shared_secret_len < shared_secret_size()) {
        *shared_secret_len = shared_secret_size();
        throw std::runtime_error("Shared secret buffer too small");
    }
    
    if (key_id_ == 0) {
        throw std::runtime_error("ECDH-P256 key not generated");
    }
    
    // Note: In PSA, our_private_key is ignored since we use the stored key_id_
    // This is a limitation of the PSA API design
    
    // Perform ECDH key agreement
    psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id_, 
        peer_public_key, peer_public_key_len, 
        shared_secret, shared_secret_size(), shared_secret_len);
    
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("ECDH-P256 shared secret computation failed");
    }
}

// =============================================================================
// MAC Implementations
// =============================================================================

// HMAC-SHA256 implementation
void MbedTLSHMACSHA256::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    ensure_psa_initialized();
    
    if (mac_len < mac_size()) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        throw std::runtime_error("HMAC-SHA256 key import failed");
    }
    
    try {
        size_t mac_output_len;
        status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), 
            message, message_len, mac, mac_len, &mac_output_len);
        
        if (status != PSA_SUCCESS) {
            throw std::runtime_error("HMAC-SHA256 computation failed");
        }
    } catch (...) {
        psa_destroy_key(key_id);
        throw;
    }
    
    psa_destroy_key(key_id);
}

bool MbedTLSHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    ensure_psa_initialized();
    
    if (mac_len != mac_size()) {
        return false;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    
    psa_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return false;
    }
    
    try {
        status = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), 
            message, message_len, mac, mac_len);
        
        psa_destroy_key(key_id);
        return status == PSA_SUCCESS;
    } catch (...) {
        psa_destroy_key(key_id);
        return false;
    }
}

// =============================================================================
// Factory Functions
// =============================================================================

// Symmetric encryption factory functions
std::unique_ptr<SymmetricAdapter> create_aes_128_gcm() {
    return std::make_unique<MbedTLSAES128GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_gcm() {
    return std::make_unique<MbedTLSAES256GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_cbc() {
    return std::make_unique<MbedTLSAES256CBC>();
}

std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305() {
    return std::make_unique<MbedTLSChaCha20Poly1305>();
}

// Asymmetric signature factory functions
std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048() {
    return std::make_unique<MbedTLSRSA2048>();
}

std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096() {
    return std::make_unique<MbedTLSRSA4096>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256() {
    return std::make_unique<MbedTLSECDSAP256>();
}

// Key exchange factory functions
std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256() {
    return std::make_unique<MbedTLSECDHP256>();
}

// MAC factory functions
std::unique_ptr<MACAdapter> create_hmac_sha256() {
    return std::make_unique<MbedTLSHMACSHA256>();
}

} // namespace mbedtls
} // namespace crypto_bench

#endif // ENABLE_MBEDTLS