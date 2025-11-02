#ifndef SATP_CLIENT_H
#define SATP_CLIENT_H

#include "satp_protocol.h"
#include "satp_encryption.h"
#include <iostream>
#include <queue>
#include <map>
#include <cstring>
#include <iomanip>

namespace SATP {

// ============================================================================
// SATP CLIENT
// ============================================================================
// Main protocol implementation for client-side operations

class SATPClient {
private:
    DeviceInfo device_info_;
    SessionInfo session_info_;
    PrivacySettings privacy_settings_;
    EncryptionManager encryption_;
    ConnectionState state_;
    
    uint16_t sequence_number_;
    std::queue<SATPMessage> send_queue_;
    std::vector<SecurityEvent> security_log_;
    
    // Statistics
    size_t messages_sent_;
    size_t messages_received_;
    size_t errors_;
    
public:
    SATPClient(const std::string& device_id, const std::string& device_type) 
        : state_(ConnectionState::DISCONNECTED),
          sequence_number_(0),
          messages_sent_(0),
          messages_received_(0),
          errors_(0) {
        
        device_info_.device_id = device_id;
        device_info_.device_type = device_type;
        device_info_.is_assistive_device = true;
        device_info_.battery_percentage = 100;
        device_info_.power_state = PowerState::FULL;
    }
    
    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================
    
    // Initiate connection with server
    bool connect() {
        std::cout << "[SATP] Initiating connection for device: " 
                  << device_info_.device_id << std::endl;
        
        state_ = ConnectionState::INITIATING;
        
        // Initialize encryption based on power state
        SecurityLevel level = determineSecurityLevel();
        if (!encryption_.initialize(level)) {
            logSecurityEvent("ENCRYPTION_INIT_FAILED", 
                           "Failed to initialize encryption", true);
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        // Create and send HELLO message
        SATPMessage hello_msg = createMessage(MessageType::HELLO, Priority::HIGH);
        
        // Add device info to payload
        std::string device_info_str = device_info_.device_id + ":" + device_info_.device_type;
        hello_msg.payload.assign(device_info_str.begin(), device_info_str.end());
        
        if (!sendMessage(hello_msg)) {
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        state_ = ConnectionState::HANDSHAKING;
        
        // Simulate receiving HELLO_ACK
        std::cout << "[SATP] Received HELLO_ACK from server" << std::endl;
        session_info_.session_id = generateSessionID();
        
        // Send KEY_EXCHANGE
        SATPMessage key_msg = createMessage(MessageType::KEY_EXCHANGE, Priority::HIGH);
        if (!sendMessage(key_msg)) {
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        // Simulate receiving SESSION_READY
        std::cout << "[SATP] Received SESSION_READY" << std::endl;
        session_info_.is_authenticated = true;
        state_ = ConnectionState::CONNECTED;
        
        logSecurityEvent("CONNECTION_ESTABLISHED", 
                        "Secure session established", false);
        
        std::cout << "[SATP] ✓ Connection established successfully" << std::endl;
        std::cout << "[SATP] Session ID: 0x" << std::hex << session_info_.session_id 
                  << std::dec << std::endl;
        std::cout << "[SATP] Security Level: " 
                  << securityLevelToString(encryption_.getSecurityLevel()) << std::endl;
        
        return true;
    }
    
    // Disconnect from server
    void disconnect() {
        if (state_ == ConnectionState::CONNECTED) {
            SATPMessage disconnect_msg = createMessage(MessageType::DISCONNECT, 
                                                       Priority::NORMAL);
            sendMessage(disconnect_msg);
        }
        state_ = ConnectionState::DISCONNECTED;
        std::cout << "[SATP] Disconnected" << std::endl;
    }
    
    // ========================================================================
    // DATA TRANSMISSION
    // ========================================================================
    
    // Send navigation data (primary use case)
    bool sendNavigationData(const NavigationData& nav_data) {
        if (!isConnected()) {
            std::cerr << "[SATP] Error: Not connected" << std::endl;
            return false;
        }
        
        // Apply privacy settings
        NavigationData processed_data = applyPrivacySettings(nav_data);
        
        // Create message
        SATPMessage msg = createMessage(MessageType::DATA, nav_data.urgency);
        
        // Serialize navigation data to payload
        msg.payload = serializeNavigationData(processed_data);
        
        // Send with encryption
        return sendMessage(msg);
    }
    
    // Send generic data
    bool sendData(const std::vector<uint8_t>& data, Priority priority = Priority::NORMAL) {
        if (!isConnected()) {
            return false;
        }
        
        SATPMessage msg = createMessage(MessageType::DATA, priority);
        msg.payload = data;
        
        return sendMessage(msg);
    }
    
    // Send heartbeat to maintain connection
    bool sendHeartbeat() {
        if (!isConnected()) {
            return false;
        }
        
        SATPMessage msg = createMessage(MessageType::HEARTBEAT, Priority::LOW);
        return sendMessage(msg);
    }
    
    // ========================================================================
    // POWER MANAGEMENT
    // ========================================================================
    
    // Update battery level (triggers security level adaptation)
    void updateBatteryLevel(uint8_t percentage) {
        device_info_.battery_percentage = percentage;
        
        PowerState old_state = device_info_.power_state;
        device_info_.power_state = determinePowerState(percentage);
        
        if (old_state != device_info_.power_state) {
            std::cout << "[SATP] Power state changed: " 
                      << powerStateToString(old_state) << " -> " 
                      << powerStateToString(device_info_.power_state) << std::endl;
            
            // Adapt security level
            SecurityLevel new_level = determineSecurityLevel();
            encryption_.updateSecurityLevel(new_level);
            
            std::cout << "[SATP] Security level adapted: " 
                      << securityLevelToString(new_level) << std::endl;
            
            logSecurityEvent("SECURITY_ADAPTATION", 
                           "Security level adjusted for power state", false);
        }
    }
    
    // ========================================================================
    // PRIVACY CONTROLS
    // ========================================================================
    
    // Update privacy settings
    void setPrivacySettings(const PrivacySettings& settings) {
        privacy_settings_ = settings;
        std::cout << "[SATP] Privacy settings updated" << std::endl;
    }
    
    // Get current privacy settings
    const PrivacySettings& getPrivacySettings() const {
        return privacy_settings_;
    }
    
    // ========================================================================
    // STATUS & MONITORING
    // ========================================================================
    
    bool isConnected() const {
        return state_ == ConnectionState::CONNECTED;
    }
    
    ConnectionState getConnectionState() const {
        return state_;
    }
    
    // Get statistics
    void printStatistics() const {
        std::cout << "\n[SATP] === CONNECTION STATISTICS ===" << std::endl;
        std::cout << "[SATP] Device ID: " << device_info_.device_id << std::endl;
        std::cout << "[SATP] Session ID: 0x" << std::hex << session_info_.session_id 
                  << std::dec << std::endl;
        std::cout << "[SATP] State: " << connectionStateToString(state_) << std::endl;
        std::cout << "[SATP] Security Level: " 
                  << securityLevelToString(encryption_.getSecurityLevel()) << std::endl;
        std::cout << "[SATP] Battery: " << (int)device_info_.battery_percentage << "%" << std::endl;
        std::cout << "[SATP] Messages Sent: " << messages_sent_ << std::endl;
        std::cout << "[SATP] Messages Received: " << messages_received_ << std::endl;
        std::cout << "[SATP] Errors: " << errors_ << std::endl;
        std::cout << "[SATP] Security Events: " << security_log_.size() << std::endl;
        std::cout << "[SATP] ==========================\n" << std::endl;
    }
    
    // Get security log
    const std::vector<SecurityEvent>& getSecurityLog() const {
        return security_log_;
    }
    
private:
    // ========================================================================
    // INTERNAL HELPER METHODS
    // ========================================================================
    
    // Create a basic SATP message
    SATPMessage createMessage(MessageType type, Priority priority) {
        SATPMessage msg;
        
        msg.header.version = SATP_VERSION;
        msg.header.message_type = static_cast<uint8_t>(type);
        msg.header.security_level = static_cast<uint8_t>(encryption_.getSecurityLevel());
        msg.header.priority = static_cast<uint8_t>(priority);
        msg.header.sequence_number = sequence_number_++;
        msg.header.payload_length = 0; // Will be updated when payload is set
        msg.header.flags = 0;
        
        msg.security_meta.session_id = session_info_.session_id;
        msg.security_meta.timestamp = getCurrentTimestamp();
        
        return msg;
    }
    
    // Send message (encrypt and add integrity check)
    bool sendMessage(SATPMessage& msg) {
        try {
            // Update payload length
            msg.header.payload_length = msg.payload.size();
            
            // Encrypt payload
            if (!msg.payload.empty()) {
                msg.payload = encryption_.encrypt(msg.payload);
            }
            
            // Calculate HMAC over header + security metadata + encrypted payload
            std::vector<uint8_t> hmac_data;
            hmac_data.insert(hmac_data.end(), 
                           reinterpret_cast<uint8_t*>(&msg.header),
                           reinterpret_cast<uint8_t*>(&msg.header) + sizeof(MessageHeader));
            hmac_data.insert(hmac_data.end(),
                           reinterpret_cast<uint8_t*>(&msg.security_meta),
                           reinterpret_cast<uint8_t*>(&msg.security_meta) + sizeof(SecurityMetadata));
            hmac_data.insert(hmac_data.end(), 
                           msg.payload.begin(), msg.payload.end());
            
            auto hmac_result = encryption_.calculateHMAC(hmac_data);
            std::memcpy(msg.hmac, hmac_result.data(), HMAC_SIZE);
            
            // Simulate network transmission
            std::cout << "[SATP] → Sending " << messageTypeToString(static_cast<MessageType>(msg.header.message_type))
                      << " (seq: " << msg.header.sequence_number 
                      << ", size: " << msg.payload.size() << " bytes)" << std::endl;
            
            messages_sent_++;
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "[SATP] Error sending message: " << e.what() << std::endl;
            errors_++;
            return false;
        }
    }
    
    // Determine security level based on power state and threat
    SecurityLevel determineSecurityLevel() const {
        switch (device_info_.power_state) {
            case PowerState::FULL:
                return SecurityLevel::LEVEL_1_MAXIMUM;
            case PowerState::BALANCED:
                return SecurityLevel::LEVEL_2_BALANCED;
            case PowerState::LOW:
                return SecurityLevel::LEVEL_3_MINIMAL;
            case PowerState::EMERGENCY:
                return SecurityLevel::LEVEL_EMERGENCY;
            default:
                return SecurityLevel::LEVEL_2_BALANCED;
        }
    }
    
    // Determine power state from battery percentage
    PowerState determinePowerState(uint8_t battery_percent) const {
        if (battery_percent > 70) return PowerState::FULL;
        if (battery_percent > 30) return PowerState::BALANCED;
        if (battery_percent > 10) return PowerState::LOW;
        return PowerState::EMERGENCY;
    }
    
    // Apply privacy settings to navigation data
    NavigationData applyPrivacySettings(const NavigationData& data) const {
        NavigationData processed = data;
        
        if (privacy_settings_.enable_location_anonymization) {
            // Reduce precision based on settings
            double precision = privacy_settings_.location_precision_meters / 111000.0; // degrees
            processed.latitude = std::round(data.latitude / precision) * precision;
            processed.longitude = std::round(data.longitude / precision) * precision;
        }
        
        return processed;
    }
    
    // Serialize navigation data
    std::vector<uint8_t> serializeNavigationData(const NavigationData& data) const {
        // Simple serialization (in real implementation, use protobuf or similar)
        std::string serialized = std::to_string(data.latitude) + "," +
                                std::to_string(data.longitude) + "," +
                                std::to_string(data.heading) + "," +
                                std::to_string(data.distance_to_obstacle) + "," +
                                data.obstacle_type;
        
        return std::vector<uint8_t>(serialized.begin(), serialized.end());
    }
    
    // Generate unique session ID
    uint64_t generateSessionID() const {
        return std::chrono::system_clock::now().time_since_epoch().count();
    }
    
    // Get current timestamp in milliseconds
    uint64_t getCurrentTimestamp() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    
    // Log security event
    void logSecurityEvent(const std::string& type, const std::string& description, 
                         bool is_critical) {
        SecurityEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.event_type = type;
        event.description = description;
        event.security_level = encryption_.getSecurityLevel();
        event.is_critical = is_critical;
        
        security_log_.push_back(event);
        
        if (is_critical) {
            std::cerr << "[SATP] ⚠ CRITICAL SECURITY EVENT: " << description << std::endl;
        }
    }
    
    // String conversion helpers
    std::string messageTypeToString(MessageType type) const {
        switch (type) {
            case MessageType::HELLO: return "HELLO";
            case MessageType::HELLO_ACK: return "HELLO_ACK";
            case MessageType::KEY_EXCHANGE: return "KEY_EXCHANGE";
            case MessageType::SESSION_READY: return "SESSION_READY";
            case MessageType::DATA: return "DATA";
            case MessageType::HEARTBEAT: return "HEARTBEAT";
            case MessageType::DISCONNECT: return "DISCONNECT";
            case MessageType::ALERT: return "ALERT";
            default: return "UNKNOWN";
        }
    }
    
    std::string securityLevelToString(SecurityLevel level) const {
        switch (level) {
            case SecurityLevel::LEVEL_1_MAXIMUM: return "MAXIMUM (Level 1)";
            case SecurityLevel::LEVEL_2_BALANCED: return "BALANCED (Level 2)";
            case SecurityLevel::LEVEL_3_MINIMAL: return "MINIMAL (Level 3)";
            case SecurityLevel::LEVEL_EMERGENCY: return "EMERGENCY";
            default: return "UNKNOWN";
        }
    }
    
    std::string powerStateToString(PowerState state) const {
        switch (state) {
            case PowerState::FULL: return "FULL (>70%)";
            case PowerState::BALANCED: return "BALANCED (30-70%)";
            case PowerState::LOW: return "LOW (10-30%)";
            case PowerState::EMERGENCY: return "EMERGENCY (<10%)";
            default: return "UNKNOWN";
        }
    }
    
    std::string connectionStateToString(ConnectionState state) const {
        switch (state) {
            case ConnectionState::DISCONNECTED: return "DISCONNECTED";
            case ConnectionState::INITIATING: return "INITIATING";
            case ConnectionState::HANDSHAKING: return "HANDSHAKING";
            case ConnectionState::CONNECTED: return "CONNECTED";
            case ConnectionState::ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }
};

} // namespace SATP

#endif // SATP_CLIENT_H
