/**
 * cryptopp_adapter.cpp - Crypto++ implementation of crypto_adapter interfaces
 */

#include "cryptopp_adapter.h"

#ifdef ENABLE_CRYPTOPP

#include <sha.h>
#include <sha3.h>
#include <blake2.h>
#include <stdexcept>
#include <cstring>
// Advanced cryptography headers
#include <aes.h>
#include <gcm.h>
#include <modes.h>
#include <chacha.h>
#include <poly1305.h>
#include <chachapoly.h>
#include <rsa.h>
#include <pssr.h>
#include <eccrypto.h>
#include <ecp.h>
#include <oids.h>
#include <osrng.h>
#include <hmac.h>
#include <xed25519.h>

namespace crypto_bench {
namespace cryptopp {

// SHA-256 implementation
void CryptoppSHA256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    CryptoPP::SHA256 hasher;
    hasher.CalculateDigest(output, data, len);
}

// SHA-512 implementation
void CryptoppSHA512::hash(const uint8_t* data, size_t len, uint8_t* output) {
    CryptoPP::SHA512 hasher;
    hasher.CalculateDigest(output, data, len);
}

// SHA3-256 implementation
void CryptoppSHA3_256::hash(const uint8_t* data, size_t len, uint8_t* output) {
    CryptoPP::SHA3_256 hasher;
    hasher.CalculateDigest(output, data, len);
}

// BLAKE2b implementation (512-bit version)
void CryptoppBLAKE2b::hash(const uint8_t* data, size_t len, uint8_t* output) {
    CryptoPP::BLAKE2b hasher;
    hasher.CalculateDigest(output, data, len);
}

// Factory functions
std::unique_ptr<HashAdapter> create_sha256() {
    return std::make_unique<CryptoppSHA256>();
}

std::unique_ptr<HashAdapter> create_sha512() {
    return std::make_unique<CryptoppSHA512>();
}

std::unique_ptr<HashAdapter> create_sha3_256() {
    return std::make_unique<CryptoppSHA3_256>();
}

std::unique_ptr<HashAdapter> create_blake2b() {
    return std::make_unique<CryptoppBLAKE2b>();
}

// =============================================================================
// Symmetric Encryption Implementations
// =============================================================================

// AES-128-GCM implementation
void CryptoppAES128GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key_len, iv, iv_len);
        
        // Use a string to collect both ciphertext and tag
        std::string output;
        CryptoPP::AuthenticatedEncryptionFilter aef(enc,
            new CryptoPP::StringSink(output),
            false, tag_len
        );

        aef.ChannelPut("AAD", aad, aad_len);
        aef.ChannelMessageEnd("AAD");
        aef.ChannelPut("", plaintext, plaintext_len);
        aef.ChannelMessageEnd("");

        // Copy ciphertext and tag from output
        std::memcpy(ciphertext, output.data(), plaintext_len);
        std::memcpy(tag, output.data() + plaintext_len, tag_len);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES-128-GCM encryption failed: " + std::string(e.what()));
    }
}

bool CryptoppAES128GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key_len, iv, iv_len);
        
        CryptoPP::AuthenticatedDecryptionFilter adf(dec,
            new CryptoPP::ArraySink(plaintext, ciphertext_len),
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END |
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            tag_len
        );
        
        adf.ChannelPut("AAD", aad, aad_len);
        adf.ChannelMessageEnd("AAD");
        adf.ChannelPut("", ciphertext, ciphertext_len);
        adf.ChannelPut("", tag, tag_len);
        adf.ChannelMessageEnd("");
        
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// AES-256-GCM implementation
void CryptoppAES256GCM::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key_len, iv, iv_len);

        // Use a string to collect both ciphertext and tag
        std::string output;
        CryptoPP::AuthenticatedEncryptionFilter aef(enc,
            new CryptoPP::StringSink(output),
            false, tag_len
        );

        aef.ChannelPut("AAD", aad, aad_len);
        aef.ChannelMessageEnd("AAD");
        aef.ChannelPut("", plaintext, plaintext_len);
        aef.ChannelMessageEnd("");

        // Copy ciphertext and tag from output
        std::memcpy(ciphertext, output.data(), plaintext_len);
        std::memcpy(tag, output.data() + plaintext_len, tag_len);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES-256-GCM encryption failed: " + std::string(e.what()));
    }
}

bool CryptoppAES256GCM::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key_len, iv, iv_len);
        
        CryptoPP::AuthenticatedDecryptionFilter adf(dec,
            new CryptoPP::ArraySink(plaintext, ciphertext_len),
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END |
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            tag_len
        );
        
        adf.ChannelPut("AAD", aad, aad_len);
        adf.ChannelMessageEnd("AAD");
        adf.ChannelPut("", ciphertext, ciphertext_len);
        adf.ChannelPut("", tag, tag_len);
        adf.ChannelMessageEnd("");
        
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// AES-256-CBC implementation
void CryptoppAES256CBC::encrypt_cbc(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* ciphertext
) {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key_len, iv, iv_len);
        
        CryptoPP::StreamTransformationFilter stf(enc,
            new CryptoPP::ArraySink(ciphertext, plaintext_len),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        );
        stf.Put(plaintext, plaintext_len);
        stf.MessageEnd();
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES-256-CBC encryption failed: " + std::string(e.what()));
    }
}

void CryptoppAES256CBC::decrypt_cbc(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* plaintext
) {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key_len, iv, iv_len);
        
        CryptoPP::StreamTransformationFilter stf(dec,
            new CryptoPP::ArraySink(plaintext, ciphertext_len),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        );
        stf.Put(ciphertext, ciphertext_len);
        stf.MessageEnd();
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES-256-CBC decryption failed: " + std::string(e.what()));
    }
}

// ChaCha20-Poly1305 implementation
void CryptoppChaCha20Poly1305::encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag, size_t tag_len
) {
    try {
        CryptoPP::ChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key, key_len, iv, iv_len);

        // Use a string to collect both ciphertext and tag
        std::string output;
        CryptoPP::AuthenticatedEncryptionFilter aef(enc,
            new CryptoPP::StringSink(output),
            false, tag_len
        );

        aef.ChannelPut("AAD", aad, aad_len);
        aef.ChannelMessageEnd("AAD");
        aef.ChannelPut("", plaintext, plaintext_len);
        aef.ChannelMessageEnd("");

        // Copy ciphertext and tag from output
        std::memcpy(ciphertext, output.data(), plaintext_len);
        std::memcpy(tag, output.data() + plaintext_len, tag_len);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed: " + std::string(e.what()));
    }
}

bool CryptoppChaCha20Poly1305::decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* plaintext
) {
    try {
        CryptoPP::ChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key, key_len, iv, iv_len);
        
        CryptoPP::AuthenticatedDecryptionFilter adf(dec,
            new CryptoPP::ArraySink(plaintext, ciphertext_len),
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END |
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            tag_len
        );
        
        adf.ChannelPut("AAD", aad, aad_len);
        adf.ChannelMessageEnd("AAD");
        adf.ChannelPut("", ciphertext, ciphertext_len);
        adf.ChannelPut("", tag, tag_len);
        adf.ChannelMessageEnd("");
        
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// =============================================================================
// Asymmetric Signature Implementations
// =============================================================================

// RSA-2048 implementation
CryptoppRSA2048::CryptoppRSA2048() 
    : private_key_(std::make_unique<CryptoPP::RSA::PrivateKey>()),
      public_key_(std::make_unique<CryptoPP::RSA::PublicKey>()) {
}

CryptoppRSA2048::~CryptoppRSA2048() = default;

void CryptoppRSA2048::generate_keypair() {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        private_key_->GenerateRandomWithKeySize(rng, 2048);
        public_key_->AssignFrom(*private_key_);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("RSA-2048 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppRSA2048::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer signer(*private_key_);
        
        size_t sig_len = signer.MaxSignatureLength();
        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            throw std::runtime_error("Signature buffer too small");
        }
        
        *signature_len = signer.SignMessage(rng, message, message_len, signature);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("RSA-2048 signing failed: " + std::string(e.what()));
    }
}

bool CryptoppRSA2048::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    try {
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier verifier(*public_key_);
        return verifier.VerifyMessage(message, message_len, signature, signature_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// RSA-4096 implementation
CryptoppRSA4096::CryptoppRSA4096() 
    : private_key_(std::make_unique<CryptoPP::RSA::PrivateKey>()),
      public_key_(std::make_unique<CryptoPP::RSA::PublicKey>()) {
}

CryptoppRSA4096::~CryptoppRSA4096() = default;

void CryptoppRSA4096::generate_keypair() {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        private_key_->GenerateRandomWithKeySize(rng, 4096);
        public_key_->AssignFrom(*private_key_);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("RSA-4096 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppRSA4096::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Signer signer(*private_key_);
        
        size_t sig_len = signer.MaxSignatureLength();
        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            throw std::runtime_error("Signature buffer too small");
        }
        
        *signature_len = signer.SignMessage(rng, message, message_len, signature);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("RSA-4096 signing failed: " + std::string(e.what()));
    }
}

bool CryptoppRSA4096::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    try {
        CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA256>::Verifier verifier(*public_key_);
        return verifier.VerifyMessage(message, message_len, signature, signature_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// ECDSA-P256 implementation
CryptoppECDSAP256::CryptoppECDSAP256() 
    : private_key_(std::make_unique<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey>()),
      public_key_(std::make_unique<CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey>()) {
}

CryptoppECDSAP256::~CryptoppECDSAP256() = default;

void CryptoppECDSAP256::generate_keypair() {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        private_key_->Initialize(rng, CryptoPP::ASN1::secp256r1());
        private_key_->MakePublicKey(*public_key_);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("ECDSA-P256 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppECDSAP256::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(*private_key_);
        
        size_t sig_len = signer.MaxSignatureLength();
        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            throw std::runtime_error("Signature buffer too small");
        }
        
        *signature_len = signer.SignMessage(rng, message, message_len, signature);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("ECDSA-P256 signing failed: " + std::string(e.what()));
    }
}

bool CryptoppECDSAP256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(*public_key_);
        return verifier.VerifyMessage(message, message_len, signature, signature_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// Ed25519 implementation
CryptoppEd25519::CryptoppEd25519()
    : private_key_(std::make_unique<CryptoPP::ed25519PrivateKey>()),
      public_key_(std::make_unique<CryptoPP::ed25519PublicKey>()) {
}

CryptoppEd25519::~CryptoppEd25519() = default;

void CryptoppEd25519::generate_keypair() {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        private_key_->GenerateRandom(rng, CryptoPP::g_nullNameValuePairs);
        private_key_->MakePublicKey(*public_key_);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Ed25519 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppEd25519::sign(
    const uint8_t* message, size_t message_len,
    uint8_t* signature, size_t* signature_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ed25519Signer signer(*private_key_);
        
        size_t sig_len = signer.SignatureLength();
        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            throw std::runtime_error("Signature buffer too small");
        }
        
        *signature_len = signer.SignMessage(rng, message, message_len, signature);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Ed25519 signing failed: " + std::string(e.what()));
    }
}

bool CryptoppEd25519::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len
) {
    try {
        CryptoPP::ed25519Verifier verifier(*public_key_);
        return verifier.VerifyMessage(message, message_len, signature, signature_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// =============================================================================
// Key Exchange Implementations
// =============================================================================

// ECDH-P256 implementation
CryptoppECDHP256::CryptoppECDHP256() 
    : domain_(std::make_unique<CryptoPP::ECDH<CryptoPP::ECP>::Domain>(CryptoPP::ASN1::secp256r1())) {
}

CryptoppECDHP256::~CryptoppECDHP256() = default;

void CryptoppECDHP256::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        
        if (*private_key_len < private_key_size() || *public_key_len < public_key_size()) {
            *private_key_len = private_key_size();
            *public_key_len = public_key_size();
            throw std::runtime_error("Key buffer too small");
        }
        
        CryptoPP::SecByteBlock priv_key(domain_->PrivateKeyLength());
        CryptoPP::SecByteBlock pub_key(domain_->PublicKeyLength());
        
        domain_->GenerateKeyPair(rng, priv_key, pub_key);
        
        std::memcpy(private_key, priv_key.data(), priv_key.size());
        std::memcpy(public_key, pub_key.data(), pub_key.size());
        
        *private_key_len = priv_key.size();
        *public_key_len = pub_key.size();
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("ECDH-P256 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppECDHP256::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    try {
        if (*shared_secret_len < shared_secret_size()) {
            *shared_secret_len = shared_secret_size();
            throw std::runtime_error("Shared secret buffer too small");
        }
        
        CryptoPP::SecByteBlock secret(domain_->AgreedValueLength());
        
        bool result = domain_->Agree(secret, 
            CryptoPP::SecByteBlock(our_private_key, our_private_key_len),
            CryptoPP::SecByteBlock(peer_public_key, peer_public_key_len));
            
        if (!result) {
            throw std::runtime_error("ECDH agreement failed");
        }
        
        std::memcpy(shared_secret, secret.data(), secret.size());
        *shared_secret_len = secret.size();
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("ECDH-P256 shared secret computation failed: " + std::string(e.what()));
    }
}

// X25519 implementation
void CryptoppX25519::generate_keypair(
    uint8_t* public_key, size_t* public_key_len,
    uint8_t* private_key, size_t* private_key_len
) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        
        if (*private_key_len < private_key_size() || *public_key_len < public_key_size()) {
            *private_key_len = private_key_size();
            *public_key_len = public_key_size();
            throw std::runtime_error("Key buffer too small");
        }
        
        CryptoPP::x25519 x25519_obj;
        CryptoPP::SecByteBlock priv_key(32), pub_key(32);
        
        x25519_obj.GenerateKeyPair(rng, priv_key, pub_key);
        
        std::memcpy(private_key, priv_key.data(), 32);
        std::memcpy(public_key, pub_key.data(), 32);
        
        *private_key_len = 32;
        *public_key_len = 32;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("X25519 key generation failed: " + std::string(e.what()));
    }
}

void CryptoppX25519::compute_shared_secret(
    const uint8_t* our_private_key, size_t our_private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_key_len,
    uint8_t* shared_secret, size_t* shared_secret_len
) {
    try {
        if (*shared_secret_len < shared_secret_size()) {
            *shared_secret_len = shared_secret_size();
            throw std::runtime_error("Shared secret buffer too small");
        }
        
        CryptoPP::x25519 x25519_obj;
        CryptoPP::SecByteBlock secret(32);
        
        bool result = x25519_obj.Agree(secret,
            CryptoPP::SecByteBlock(our_private_key, our_private_key_len),
            CryptoPP::SecByteBlock(peer_public_key, peer_public_key_len));
            
        if (!result) {
            throw std::runtime_error("X25519 agreement failed");
        }
        
        std::memcpy(shared_secret, secret.data(), 32);
        *shared_secret_len = 32;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("X25519 shared secret computation failed: " + std::string(e.what()));
    }
}

// =============================================================================
// MAC Implementations
// =============================================================================

// HMAC-SHA256 implementation
void CryptoppHMACSHA256::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    try {
        if (mac_len < mac_size()) {
            throw std::runtime_error("MAC buffer too small");
        }
        
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key_len);
        hmac.CalculateDigest(mac, message, message_len);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("HMAC-SHA256 computation failed: " + std::string(e.what()));
    }
}

bool CryptoppHMACSHA256::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    try {
        if (mac_len != mac_size()) {
            return false;
        }
        
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, key_len);
        return hmac.VerifyDigest(mac, message, message_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// Poly1305 implementation
void CryptoppPoly1305::compute(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    uint8_t* mac, size_t mac_len
) {
    try {
        if (mac_len < mac_size()) {
            throw std::runtime_error("MAC buffer too small");
        }
        if (key_len != key_size()) {
            throw std::runtime_error("Invalid key size for Poly1305");
        }
        
        CryptoPP::Poly1305<CryptoPP::AES> poly1305;
        poly1305.SetKey(key, key_len);
        poly1305.CalculateDigest(mac, message, message_len);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Poly1305 computation failed: " + std::string(e.what()));
    }
}

bool CryptoppPoly1305::verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* mac, size_t mac_len
) {
    try {
        if (mac_len != mac_size() || key_len != key_size()) {
            return false;
        }
        
        CryptoPP::Poly1305<CryptoPP::AES> poly1305;
        poly1305.SetKey(key, key_len);
        return poly1305.VerifyDigest(mac, message, message_len);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

// =============================================================================
// Factory Functions
// =============================================================================

// Symmetric encryption factory functions
std::unique_ptr<SymmetricAdapter> create_aes_128_gcm() {
    return std::make_unique<CryptoppAES128GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_gcm() {
    return std::make_unique<CryptoppAES256GCM>();
}

std::unique_ptr<SymmetricAdapter> create_aes_256_cbc() {
    return std::make_unique<CryptoppAES256CBC>();
}

std::unique_ptr<SymmetricAdapter> create_chacha20_poly1305() {
    return std::make_unique<CryptoppChaCha20Poly1305>();
}

// Asymmetric signature factory functions
std::unique_ptr<AsymmetricSignAdapter> create_rsa_2048() {
    return std::make_unique<CryptoppRSA2048>();
}

std::unique_ptr<AsymmetricSignAdapter> create_rsa_4096() {
    return std::make_unique<CryptoppRSA4096>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ecdsa_p256() {
    return std::make_unique<CryptoppECDSAP256>();
}

std::unique_ptr<AsymmetricSignAdapter> create_ed25519() {
    return std::make_unique<CryptoppEd25519>();
}

// Key exchange factory functions
std::unique_ptr<KeyExchangeAdapter> create_ecdh_p256() {
    return std::make_unique<CryptoppECDHP256>();
}

std::unique_ptr<KeyExchangeAdapter> create_x25519() {
    return std::make_unique<CryptoppX25519>();
}

// MAC factory functions
std::unique_ptr<MACAdapter> create_hmac_sha256() {
    return std::make_unique<CryptoppHMACSHA256>();
}

std::unique_ptr<MACAdapter> create_poly1305() {
    return std::make_unique<CryptoppPoly1305>();
}

} // namespace cryptopp
} // namespace crypto_bench

#endif // ENABLE_CRYPTOPP