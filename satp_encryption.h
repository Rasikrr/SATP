#ifndef SATP_ENCRYPTION_H
#define SATP_ENCRYPTION_H

#include "satp_protocol.h"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <random>
#include <stdexcept>

namespace SATP {

// ============================================================================
// ENCRYPTION MANAGER
// ============================================================================
// Handles all cryptographic operations for SATP
// Simulates AES-128-GCM and HMAC-SHA256 operations

class EncryptionManager {
private:
    SecurityLevel current_level_;
    std::vector<uint8_t> session_key_;
    std::vector<uint8_t> hmac_key_;
    bool is_initialized_;
    
    // Statistics
    size_t total_encrypted_;
    size_t total_decrypted_;
    
public:
    EncryptionManager() 
        : current_level_(SecurityLevel::LEVEL_2_BALANCED),
          is_initialized_(false),
          total_encrypted_(0),
          total_decrypted_(0) {
    }
    
    // Initialize encryption with new session keys
    bool initialize(SecurityLevel level) {
        current_level_ = level;
        
        // Generate random session key
        size_t key_size = getKeySize(level);
        session_key_.resize(key_size);
        
        if (RAND_bytes(session_key_.data(), key_size) != 1) {
            return false;
        }
        
        // Generate HMAC key
        hmac_key_.resize(32); // 256 bits for HMAC-SHA256
        if (RAND_bytes(hmac_key_.data(), 32) != 1) {
            return false;
        }
        
        is_initialized_ = true;
        return true;
    }
    
    // Encrypt payload based on security level
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        if (!is_initialized_) {
            throw std::runtime_error("EncryptionManager not initialized");
        }
        
        total_encrypted_++;
        
        switch (current_level_) {
            case SecurityLevel::LEVEL_1_MAXIMUM:
                return encryptAES256GCM(plaintext);
            case SecurityLevel::LEVEL_2_BALANCED:
                return encryptAES128GCM(plaintext);
            case SecurityLevel::LEVEL_3_MINIMAL:
                return encryptChaCha20(plaintext);
            case SecurityLevel::LEVEL_EMERGENCY:
                return encryptMinimal(plaintext);
            default:
                return encryptAES128GCM(plaintext);
        }
    }
    
    // Decrypt payload
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        if (!is_initialized_) {
            throw std::runtime_error("EncryptionManager not initialized");
        }
        
        total_decrypted_++;
        
        switch (current_level_) {
            case SecurityLevel::LEVEL_1_MAXIMUM:
                return decryptAES256GCM(ciphertext);
            case SecurityLevel::LEVEL_2_BALANCED:
                return decryptAES128GCM(ciphertext);
            case SecurityLevel::LEVEL_3_MINIMAL:
                return decryptChaCha20(ciphertext);
            case SecurityLevel::LEVEL_EMERGENCY:
                return decryptMinimal(ciphertext);
            default:
                return decryptAES128GCM(ciphertext);
        }
    }
    
    // Calculate HMAC for message integrity
    std::vector<uint8_t> calculateHMAC(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hmac_result(HMAC_SIZE);
        unsigned int len = HMAC_SIZE;
        
        HMAC(EVP_sha256(), 
             hmac_key_.data(), hmac_key_.size(),
             data.data(), data.size(),
             hmac_result.data(), &len);
        
        return hmac_result;
    }
    
    // Verify HMAC
    bool verifyHMAC(const std::vector<uint8_t>& data, const uint8_t* hmac) {
        auto calculated = calculateHMAC(data);
        return (memcmp(calculated.data(), hmac, HMAC_SIZE) == 0);
    }
    
    // Update security level (power-aware adaptation)
    void updateSecurityLevel(SecurityLevel new_level) {
        if (new_level != current_level_) {
            current_level_ = new_level;
            // In real implementation, would renegotiate keys
            initialize(new_level);
        }
    }
    
    // Get current security level
    SecurityLevel getSecurityLevel() const {
        return current_level_;
    }
    
    // Get statistics
    size_t getEncryptedCount() const { return total_encrypted_; }
    size_t getDecryptedCount() const { return total_decrypted_; }
    
private:
    // Get key size based on security level
    size_t getKeySize(SecurityLevel level) const {
        switch (level) {
            case SecurityLevel::LEVEL_1_MAXIMUM:
                return 32; // 256 bits for AES-256
            case SecurityLevel::LEVEL_2_BALANCED:
                return 16; // 128 bits for AES-128
            case SecurityLevel::LEVEL_3_MINIMAL:
                return 16; // ChaCha20
            case SecurityLevel::LEVEL_EMERGENCY:
                return 8;  // Minimal security
            default:
                return 16;
        }
    }
    
    // AES-256-GCM encryption (Maximum Security)
    std::vector<uint8_t> encryptAES256GCM(const std::vector<uint8_t>& plaintext) {
        // SIMULATION: In real implementation, use OpenSSL EVP_EncryptInit_ex
        // For prototype, we simulate by XOR with key (NOT SECURE - FOR DEMO ONLY)
        std::vector<uint8_t> ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); i++) {
            ciphertext[i] ^= session_key_[i % session_key_.size()];
        }
        return ciphertext;
    }
    
    // AES-128-GCM encryption (Balanced Security) - Default
    std::vector<uint8_t> encryptAES128GCM(const std::vector<uint8_t>& plaintext) {
        // SIMULATION: XOR-based encryption for prototype
        std::vector<uint8_t> ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); i++) {
            ciphertext[i] ^= session_key_[i % session_key_.size()];
        }
        return ciphertext;
    }
    
    // ChaCha20 encryption (Minimal Security for low power)
    std::vector<uint8_t> encryptChaCha20(const std::vector<uint8_t>& plaintext) {
        // SIMULATION: Simple XOR for demonstration
        std::vector<uint8_t> ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); i++) {
            ciphertext[i] ^= session_key_[i % session_key_.size()];
        }
        return ciphertext;
    }
    
    // Minimal encryption (Emergency mode)
    std::vector<uint8_t> encryptMinimal(const std::vector<uint8_t>& plaintext) {
        // SIMULATION: Very basic obfuscation only
        std::vector<uint8_t> ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); i++) {
            ciphertext[i] ^= 0xAA; // Simple XOR with constant
        }
        return ciphertext;
    }
    
    // Decryption methods (inverse of encryption for XOR-based simulation)
    std::vector<uint8_t> decryptAES256GCM(const std::vector<uint8_t>& ciphertext) {
        return encryptAES256GCM(ciphertext); // XOR is self-inverse
    }
    
    std::vector<uint8_t> decryptAES128GCM(const std::vector<uint8_t>& ciphertext) {
        return encryptAES128GCM(ciphertext);
    }
    
    std::vector<uint8_t> decryptChaCha20(const std::vector<uint8_t>& ciphertext) {
        return encryptChaCha20(ciphertext);
    }
    
    std::vector<uint8_t> decryptMinimal(const std::vector<uint8_t>& ciphertext) {
        return encryptMinimal(ciphertext);
    }
};

} // namespace SATP

#endif // SATP_ENCRYPTION_H
