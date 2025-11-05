/**
 * mbedtls_adapter.cpp - mbedTLS implementation of crypto_adapter interfaces
 */

#include "mbedtls_adapter.h"

#ifdef ENABLE_MBEDTLS

#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/sha3.h>
#include <mbedtls/gcm.h>
#include <mbedtls/cipher.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <stdexcept>
#include <cstring>

namespace crypto_bench {
namespace mbedtls {

// SHA-256 implementation
void MbedTLSSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    mbedtls_sha256(data, len, output, 0);  // 0 = SHA-256, 1 = SHA-224
}

// SHA-512 implementation
void MbedTLSSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    mbedtls_sha512(data, len, output, 0);  // 0 = SHA-512, 1 = SHA-384
}

// SHA3-256 implementation
void MbedTLSSHA3_256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    mbedtls_sha3(MBEDTLS_SHA3_256, data, len, output, 32);
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
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    try {
        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
        if (ret != 0) {
            throw std::runtime_error("AES-128-GCM key setup failed");
        }
        
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
            plaintext_len, iv, iv_len, aad, aad_len,
            plaintext, ciphertext, tag_len, tag);
        
        if (ret != 0) {
            throw std::runtime_error("AES-128-GCM encryption failed");
        }
    } catch (...) {
        mbedtls_gcm_free(&gcm);
        throw;
    }
    
    mbedtls_gcm_free(&gcm);
}

bool MbedTLSAES128GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    try {
        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
        if (ret != 0) {
            mbedtls_gcm_free(&gcm);
            return false;
        }
        
        ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, iv_len,
            aad, aad_len, tag, tag_len, ciphertext, plaintext);
        
        mbedtls_gcm_free(&gcm);
        return ret == 0;
    } catch (...) {
        mbedtls_gcm_free(&gcm);
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
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    try {
        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
        if (ret != 0) {
            throw std::runtime_error("AES-256-GCM key setup failed");
        }
        
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
            plaintext_len, iv, iv_len, aad, aad_len,
            plaintext, ciphertext, tag_len, tag);
        
        if (ret != 0) {
            throw std::runtime_error("AES-256-GCM encryption failed");
        }
    } catch (...) {
        mbedtls_gcm_free(&gcm);
        throw;
    }
    
    mbedtls_gcm_free(&gcm);
}

bool MbedTLSAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    try {
        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);
        if (ret != 0) {
            mbedtls_gcm_free(&gcm);
            return false;
        }
        
        ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, iv_len,
            aad, aad_len, tag, tag_len, ciphertext, plaintext);
        
        mbedtls_gcm_free(&gcm);
        return ret == 0;
    } catch (...) {
        mbedtls_gcm_free(&gcm);
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
    mbedtls_cipher_context_t cipher;
    mbedtls_cipher_init(&cipher);
    
    try {
        const mbedtls_cipher_info_t* cipher_info = 
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        if (!cipher_info) {
            throw std::runtime_error("AES-256-CBC cipher info not found");
        }
        
        int ret = mbedtls_cipher_setup(&cipher, cipher_info);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC setup failed");
        }
        
        ret = mbedtls_cipher_setkey(&cipher, key, key_len * 8, MBEDTLS_ENCRYPT);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC key setup failed");
        }
        
        ret = mbedtls_cipher_set_iv(&cipher, iv, iv_len);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC IV setup failed");
        }
        
        size_t olen = 0;
        ret = mbedtls_cipher_update(&cipher, plaintext, plaintext_len, ciphertext, &olen);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC encryption failed");
        }
        
        size_t final_len = 0;
        ret = mbedtls_cipher_finish(&cipher, ciphertext + olen, &final_len);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC encryption finish failed");
        }
    } catch (...) {
        mbedtls_cipher_free(&cipher);
        throw;
    }
    
    mbedtls_cipher_free(&cipher);
}

void MbedTLSAES256CBC::decrypt_cbc(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext
) {
    mbedtls_cipher_context_t cipher;
    mbedtls_cipher_init(&cipher);
    
    try {
        const mbedtls_cipher_info_t* cipher_info = 
            mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        if (!cipher_info) {
            throw std::runtime_error("AES-256-CBC cipher info not found");
        }
        
        int ret = mbedtls_cipher_setup(&cipher, cipher_info);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC setup failed");
        }
        
        ret = mbedtls_cipher_setkey(&cipher, key, key_len * 8, MBEDTLS_DECRYPT);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC key setup failed");
        }
        
        ret = mbedtls_cipher_set_iv(&cipher, iv, iv_len);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC IV setup failed");
        }
        
        size_t olen = 0;
        ret = mbedtls_cipher_update(&cipher, ciphertext, ciphertext_len, plaintext, &olen);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC decryption failed");
        }
        
        size_t final_len = 0;
        ret = mbedtls_cipher_finish(&cipher, plaintext + olen, &final_len);
        if (ret != 0) {
            throw std::runtime_error("AES-256-CBC decryption finish failed");
        }
    } catch (...) {
        mbedtls_cipher_free(&cipher);
        throw;
    }
    
    mbedtls_cipher_free(&cipher);
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
    mbedtls_chachapoly_context chachapoly;
    mbedtls_chachapoly_init(&chachapoly);
    
    try {
        int ret = mbedtls_chachapoly_setkey(&chachapoly, key);
        if (ret != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 key setup failed");
        }
        
        ret = mbedtls_chachapoly_encrypt_and_tag(&chachapoly, plaintext_len,
            iv, aad, aad_len, plaintext, ciphertext, tag);
        
        if (ret != 0) {
            throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
        }
    } catch (...) {
        mbedtls_chachapoly_free(&chachapoly);
        throw;
    }
    
    mbedtls_chachapoly_free(&chachapoly);
}

bool MbedTLSChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    mbedtls_chachapoly_context chachapoly;
    mbedtls_chachapoly_init(&chachapoly);
    
    try {
        int ret = mbedtls_chachapoly_setkey(&chachapoly, key);
        if (ret != 0) {
            mbedtls_chachapoly_free(&chachapoly);
            return false;
        }
        
        ret = mbedtls_chachapoly_auth_decrypt(&chachapoly, ciphertext_len,
            iv, aad, aad_len, tag, ciphertext, plaintext);
        
        mbedtls_chachapoly_free(&chachapoly);
        return ret == 0;
    } catch (...) {
        mbedtls_chachapoly_free(&chachapoly);
        return false;
    }
}

// =============================================================================
// Asymmetric Signature Implementations
// =============================================================================

// RSA-2048 implementation
MbedTLSRSA2048::MbedTLSRSA2048() 
    : rsa_ctx_(std::make_unique<mbedtls_rsa_context>()),
      ctr_drbg_(std::make_unique<mbedtls_ctr_drbg_context>()),
      entropy_(std::make_unique<mbedtls_entropy_context>()) {
    
    mbedtls_rsa_init(rsa_ctx_.get());
    mbedtls_ctr_drbg_init(ctr_drbg_.get());
    mbedtls_entropy_init(entropy_.get());
    
    const char* pers = "rsa_2048";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg_.get(), mbedtls_entropy_func, 
        entropy_.get(), (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        throw std::runtime_error("RSA-2048 RNG initialization failed");
    }
}

MbedTLSRSA2048::~MbedTLSRSA2048() {
    if (rsa_ctx_) mbedtls_rsa_free(rsa_ctx_.get());
    if (ctr_drbg_) mbedtls_ctr_drbg_free(ctr_drbg_.get());
    if (entropy_) mbedtls_entropy_free(entropy_.get());
}

void MbedTLSRSA2048::generate_keypair() {
    int ret = mbedtls_rsa_gen_key(rsa_ctx_.get(), mbedtls_ctr_drbg_random, 
        ctr_drbg_.get(), 2048, 65537);
    if (ret != 0) {
        throw std::runtime_error("RSA-2048 key generation failed");
    }
}

void MbedTLSRSA2048::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        throw std::runtime_error("RSA-2048 hash computation failed");
    }
    
    ret = mbedtls_rsa_pkcs1_sign(rsa_ctx_.get(), mbedtls_ctr_drbg_random, 
        ctr_drbg_.get(), MBEDTLS_MD_SHA256, 32, hash, signature);
    if (ret != 0) {
        throw std::runtime_error("RSA-2048 signing failed");
    }
    
    *signature_len = signature_size();
}

bool MbedTLSRSA2048::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        return false;
    }
    
    ret = mbedtls_rsa_pkcs1_verify(rsa_ctx_.get(), MBEDTLS_MD_SHA256, 
        32, hash, signature);
    return ret == 0;
}

// RSA-4096 implementation
MbedTLSRSA4096::MbedTLSRSA4096() 
    : rsa_ctx_(std::make_unique<mbedtls_rsa_context>()),
      ctr_drbg_(std::make_unique<mbedtls_ctr_drbg_context>()),
      entropy_(std::make_unique<mbedtls_entropy_context>()) {
    
    mbedtls_rsa_init(rsa_ctx_.get());
    mbedtls_ctr_drbg_init(ctr_drbg_.get());
    mbedtls_entropy_init(entropy_.get());
    
    const char* pers = "rsa_4096";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg_.get(), mbedtls_entropy_func, 
        entropy_.get(), (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        throw std::runtime_error("RSA-4096 RNG initialization failed");
    }
}

MbedTLSRSA4096::~MbedTLSRSA4096() {
    if (rsa_ctx_) mbedtls_rsa_free(rsa_ctx_.get());
    if (ctr_drbg_) mbedtls_ctr_drbg_free(ctr_drbg_.get());
    if (entropy_) mbedtls_entropy_free(entropy_.get());
}

void MbedTLSRSA4096::generate_keypair() {
    int ret = mbedtls_rsa_gen_key(rsa_ctx_.get(), mbedtls_ctr_drbg_random, 
        ctr_drbg_.get(), 4096, 65537);
    if (ret != 0) {
        throw std::runtime_error("RSA-4096 key generation failed");
    }
}

void MbedTLSRSA4096::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        throw std::runtime_error("RSA-4096 hash computation failed");
    }
    
    ret = mbedtls_rsa_pkcs1_sign(rsa_ctx_.get(), mbedtls_ctr_drbg_random, 
        ctr_drbg_.get(), MBEDTLS_MD_SHA256, 32, hash, signature);
    if (ret != 0) {
        throw std::runtime_error("RSA-4096 signing failed");
    }
    
    *signature_len = signature_size();
}

bool MbedTLSRSA4096::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        return false;
    }
    
    ret = mbedtls_rsa_pkcs1_verify(rsa_ctx_.get(), MBEDTLS_MD_SHA256, 
        32, hash, signature);
    return ret == 0;
}

// ECDSA-P256 implementation
MbedTLSECDSAP256::MbedTLSECDSAP256() 
    : ecdsa_ctx_(std::make_unique<mbedtls_ecdsa_context>()),
      ctr_drbg_(std::make_unique<mbedtls_ctr_drbg_context>()),
      entropy_(std::make_unique<mbedtls_entropy_context>()) {
    
    mbedtls_ecdsa_init(ecdsa_ctx_.get());
    mbedtls_ctr_drbg_init(ctr_drbg_.get());
    mbedtls_entropy_init(entropy_.get());
    
    const char* pers = "ecdsa_p256";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg_.get(), mbedtls_entropy_func, 
        entropy_.get(), (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        throw std::runtime_error("ECDSA-P256 RNG initialization failed");
    }
}

MbedTLSECDSAP256::~MbedTLSECDSAP256() {
    if (ecdsa_ctx_) mbedtls_ecdsa_free(ecdsa_ctx_.get());
    if (ctr_drbg_) mbedtls_ctr_drbg_free(ctr_drbg_.get());
    if (entropy_) mbedtls_entropy_free(entropy_.get());
}

void MbedTLSECDSAP256::generate_keypair() {
    int ret = mbedtls_ecdsa_genkey(ecdsa_ctx_.get(), MBEDTLS_ECP_DP_SECP256R1, 
        mbedtls_ctr_drbg_random, ctr_drbg_.get());
    if (ret != 0) {
        throw std::runtime_error("ECDSA-P256 key generation failed");
    }
}

void MbedTLSECDSAP256::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        throw std::runtime_error("ECDSA-P256 hash computation failed");
    }
    
    ret = mbedtls_ecdsa_write_signature(ecdsa_ctx_.get(), MBEDTLS_MD_SHA256,
        hash, 32, signature, signature_len, mbedtls_ctr_drbg_random, ctr_drbg_.get());
    if (ret != 0) {
        throw std::runtime_error("ECDSA-P256 signing failed");
    }
}

bool MbedTLSECDSAP256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    unsigned char hash[32];
    int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
        message, message_len, hash);
    if (ret != 0) {
        return false;
    }
    
    ret = mbedtls_ecdsa_read_signature(ecdsa_ctx_.get(), hash, 32, 
        signature, signature_len);
    return ret == 0;
}

// =============================================================================
// Key Exchange Implementations
// =============================================================================

// ECDH-P256 implementation
MbedTLSECDHP256::MbedTLSECDHP256() 
    : ecdh_ctx_(std::make_unique<mbedtls_ecdh_context>()),
      ctr_drbg_(std::make_unique<mbedtls_ctr_drbg_context>()),
      entropy_(std::make_unique<mbedtls_entropy_context>()) {
    
    mbedtls_ecdh_init(ecdh_ctx_.get());
    mbedtls_ctr_drbg_init(ctr_drbg_.get());
    mbedtls_entropy_init(entropy_.get());
    
    const char* pers = "ecdh_p256";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg_.get(), mbedtls_entropy_func, 
        entropy_.get(), (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        throw std::runtime_error("ECDH-P256 RNG initialization failed");
    }
    
    ret = mbedtls_ecp_group_load(&ecdh_ctx_->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        throw std::runtime_error("ECDH-P256 group setup failed");
    }
}

MbedTLSECDHP256::~MbedTLSECDHP256() {
    if (ecdh_ctx_) mbedtls_ecdh_free(ecdh_ctx_.get());
    if (ctr_drbg_) mbedtls_ctr_drbg_free(ctr_drbg_.get());
    if (entropy_) mbedtls_entropy_free(entropy_.get());
}

void MbedTLSECDHP256::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    if (*public_key_len < public_key_size() || *private_key_len < private_key_size()) {
        *public_key_len = public_key_size();
        *private_key_len = private_key_size();
        throw std::runtime_error("Key buffer too small");
    }
    
    int ret = mbedtls_ecdh_gen_public(&ecdh_ctx_->grp, &ecdh_ctx_->d, &ecdh_ctx_->Q,
        mbedtls_ctr_drbg_random, ctr_drbg_.get());
    if (ret != 0) {
        throw std::runtime_error("ECDH-P256 key generation failed");
    }
    
    // Export private key
    ret = mbedtls_mpi_write_binary(&ecdh_ctx_->d, private_key, private_key_size());
    if (ret != 0) {
        throw std::runtime_error("ECDH-P256 private key export failed");
    }
    
    // Export public key (uncompressed format)
    ret = mbedtls_ecp_point_write_binary(&ecdh_ctx_->grp, &ecdh_ctx_->Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED, public_key_len, public_key, public_key_size());
    if (ret != 0) {
        throw std::runtime_error("ECDH-P256 public key export failed");
    }
    
    *private_key_len = private_key_size();
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
    
    mbedtls_ecp_point peer_point;
    mbedtls_mpi our_private;
    mbedtls_mpi shared;
    
    mbedtls_ecp_point_init(&peer_point);
    mbedtls_mpi_init(&our_private);
    mbedtls_mpi_init(&shared);
    
    try {
        // Import our private key
        int ret = mbedtls_mpi_read_binary(&our_private, our_private_key, our_private_key_len);
        if (ret != 0) {
            throw std::runtime_error("ECDH-P256 private key import failed");
        }
        
        // Import peer public key
        ret = mbedtls_ecp_point_read_binary(&ecdh_ctx_->grp, &peer_point,
            peer_public_key, peer_public_key_len);
        if (ret != 0) {
            throw std::runtime_error("ECDH-P256 peer public key import failed");
        }
        
        // Compute shared secret
        ret = mbedtls_ecdh_compute_shared(&ecdh_ctx_->grp, &shared, &peer_point, 
            &our_private, mbedtls_ctr_drbg_random, ctr_drbg_.get());
        if (ret != 0) {
            throw std::runtime_error("ECDH-P256 shared secret computation failed");
        }
        
        // Export shared secret
        ret = mbedtls_mpi_write_binary(&shared, shared_secret, shared_secret_size());
        if (ret != 0) {
            throw std::runtime_error("ECDH-P256 shared secret export failed");
        }
        
        *shared_secret_len = shared_secret_size();
    } catch (...) {
        mbedtls_ecp_point_free(&peer_point);
        mbedtls_mpi_free(&our_private);
        mbedtls_mpi_free(&shared);
        throw;
    }
    
    mbedtls_ecp_point_free(&peer_point);
    mbedtls_mpi_free(&our_private);
    mbedtls_mpi_free(&shared);
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
    if (mac_len < mac_size()) {
        throw std::runtime_error("MAC buffer too small");
    }
    
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        throw std::runtime_error("SHA256 MD info not found");
    }
    
    int ret = mbedtls_md_hmac(md_info, key, key_len, message, message_len, mac);
    if (ret != 0) {
        throw std::runtime_error("HMAC-SHA256 computation failed");
    }
}

bool MbedTLSHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    if (mac_len != mac_size()) {
        return false;
    }
    
    try {
        unsigned char computed_mac[32];
        compute(message, message_len, key, key_len, computed_mac, sizeof(computed_mac));
        
        // Constant-time comparison
        int diff = 0;
        for (size_t i = 0; i < mac_size(); i++) {
            diff |= mac[i] ^ computed_mac[i];
        }
        return diff == 0;
    } catch (...) {
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