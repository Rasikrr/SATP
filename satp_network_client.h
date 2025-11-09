#ifndef SATP_NETWORK_CLIENT_H
#define SATP_NETWORK_CLIENT_H

#include "satp_protocol.h"
#include "satp_encryption.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

namespace SATP {

// ============================================================================
// SATP NETWORK CLIENT (Real UDP Implementation)
// ============================================================================
// Client implementation with actual UDP socket communication

class SATPNetworkClient {
private:
    // Network components
    int udp_socket_;
    struct sockaddr_in server_addr_;
    bool is_socket_initialized_;
    
    // Protocol components
    DeviceInfo device_info_;
    SessionInfo session_info_;
    PrivacySettings privacy_settings_;
    EncryptionManager encryption_;
    ConnectionState state_;
    
    uint16_t sequence_number_;
    std::vector<SecurityEvent> security_log_;
    
    // Statistics
    size_t messages_sent_;
    size_t messages_received_;
    size_t errors_;
    size_t bytes_sent_;
    size_t bytes_received_;
    
public:
    SATPNetworkClient(const std::string& device_id, const std::string& device_type)
        : udp_socket_(-1),
          is_socket_initialized_(false),
          state_(ConnectionState::DISCONNECTED),
          sequence_number_(0),
          messages_sent_(0),
          messages_received_(0),
          errors_(0),
          bytes_sent_(0),
          bytes_received_(0) {
        
        device_info_.device_id = device_id;
        device_info_.device_type = device_type;
        device_info_.is_assistive_device = true;
        device_info_.battery_percentage = 100;
        device_info_.power_state = PowerState::FULL;
        
        memset(&server_addr_, 0, sizeof(server_addr_));
    }
    
    ~SATPNetworkClient() {
        disconnect();
        if (udp_socket_ >= 0) {
            close(udp_socket_);
        }
    }
    
    // ========================================================================
    // NETWORK INITIALIZATION
    // ========================================================================
    
    bool initializeSocket(const std::string& server_ip, uint16_t port) {
        std::cout << "[SATP-NET] Initializing UDP socket..." << std::endl;
        
        // Create UDP socket
        udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket_ < 0) {
            std::cerr << "[SATP-NET] ✗ Failed to create UDP socket: " 
                      << strerror(errno) << std::endl;
            return false;
        }
        
        // Set socket timeout for receive operations
        struct timeval tv;
        tv.tv_sec = 5;  // 5 second timeout
        tv.tv_usec = 0;
        setsockopt(udp_socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Configure server address
        server_addr_.sin_family = AF_INET;
        server_addr_.sin_port = htons(port);
        
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr_.sin_addr) <= 0) {
            std::cerr << "[SATP-NET] ✗ Invalid server IP address: " 
                      << server_ip << std::endl;
            close(udp_socket_);
            udp_socket_ = -1;
            return false;
        }
        
        is_socket_initialized_ = true;
        std::cout << "[SATP-NET] ✓ UDP socket initialized" << std::endl;
        std::cout << "[SATP-NET] Server: " << server_ip << ":" << port << std::endl;
        
        return true;
    }
    
    // ========================================================================
    // CONNECTION MANAGEMENT
    // ========================================================================
    
    bool connect() {
        if (!is_socket_initialized_) {
            std::cerr << "[SATP-NET] ✗ Socket not initialized. Call initializeSocket() first" << std::endl;
            return false;
        }
        
        std::cout << "\n[SATP] ═══ Starting Connection Handshake ═══" << std::endl;
        std::cout << "[SATP] Device: " << device_info_.device_id << std::endl;
        
        state_ = ConnectionState::INITIATING;
        
        // Initialize encryption with PSK (Pre-Shared Key for IoT)
        SecurityLevel level = determineSecurityLevel();
        std::string psk = "SATP_SECRET_KEY_2024_IoT_Assistive_Device";  // PSK for demo
        if (!encryption_.initializeWithPSK(level, psk)) {
            logSecurityEvent("ENCRYPTION_INIT_FAILED", 
                           "Failed to initialize encryption", true);
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        std::cout << "[SATP] ✓ Encryption initialized with PSK: " 
                  << securityLevelToString(level) << std::endl;
        
        // Step 1: Send HELLO
        std::cout << "\n[SATP] Step 1/3: Sending HELLO..." << std::endl;
        SATPMessage hello_msg = createMessage(MessageType::HELLO, Priority::HIGH);
        std::string device_info_str = device_info_.device_id + ":" + device_info_.device_type;
        hello_msg.payload.assign(device_info_str.begin(), device_info_str.end());
        
        if (!sendMessageUDP(hello_msg)) {
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        // Step 2: Wait for HELLO_ACK
        std::cout << "[SATP] Step 2/3: Waiting for HELLO_ACK..." << std::endl;
        state_ = ConnectionState::HANDSHAKING;
        
        SATPMessage hello_ack;
        if (!receiveMessageUDP(hello_ack)) {
            std::cerr << "[SATP] ✗ No HELLO_ACK received from server" << std::endl;
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        if (static_cast<MessageType>(hello_ack.header.message_type) != MessageType::HELLO_ACK) {
            std::cerr << "[SATP] ✗ Expected HELLO_ACK, got different message type" << std::endl;
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        std::cout << "[SATP] ✓ HELLO_ACK received" << std::endl;
        session_info_.session_id = hello_ack.security_meta.session_id;
        
        // Step 3: Send KEY_EXCHANGE
        std::cout << "[SATP] Step 3/3: Sending KEY_EXCHANGE..." << std::endl;
        SATPMessage key_msg = createMessage(MessageType::KEY_EXCHANGE, Priority::HIGH);
        if (!sendMessageUDP(key_msg)) {
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        // Wait for SESSION_READY
        SATPMessage session_ready;
        if (!receiveMessageUDP(session_ready)) {
            std::cerr << "[SATP] ✗ No SESSION_READY received" << std::endl;
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        if (static_cast<MessageType>(session_ready.header.message_type) != MessageType::SESSION_READY) {
            std::cerr << "[SATP] ✗ Expected SESSION_READY" << std::endl;
            state_ = ConnectionState::ERROR;
            return false;
        }
        
        std::cout << "[SATP] ✓ SESSION_READY received" << std::endl;
        
        // Connection established
        session_info_.is_authenticated = true;
        state_ = ConnectionState::CONNECTED;
        
        logSecurityEvent("CONNECTION_ESTABLISHED", 
                        "Secure UDP session established", false);
        
        std::cout << "\n[SATP] ═══════════════════════════════════" << std::endl;
        std::cout << "[SATP] ✓✓✓ CONNECTION ESTABLISHED ✓✓✓" << std::endl;
        std::cout << "[SATP] ═══════════════════════════════════" << std::endl;
        std::cout << "[SATP] Session ID: 0x" << std::hex << session_info_.session_id 
                  << std::dec << std::endl;
        std::cout << "[SATP] Security Level: " 
                  << securityLevelToString(encryption_.getSecurityLevel()) << std::endl;
        std::cout << "[SATP] Transport: UDP over port " 
                  << ntohs(server_addr_.sin_port) << std::endl;
        std::cout << "[SATP] ═══════════════════════════════════\n" << std::endl;
        
        return true;
    }
    
    void disconnect() {
        if (state_ == ConnectionState::CONNECTED) {
            std::cout << "[SATP] Disconnecting..." << std::endl;
            SATPMessage disconnect_msg = createMessage(MessageType::DISCONNECT, 
                                                       Priority::NORMAL);
            sendMessageUDP(disconnect_msg);
        }
        state_ = ConnectionState::DISCONNECTED;
        std::cout << "[SATP] ✓ Disconnected" << std::endl;
    }
    
    // ========================================================================
    // DATA TRANSMISSION
    // ========================================================================
    
    bool sendNavigationData(const NavigationData& nav_data) {
        if (!isConnected()) {
            std::cerr << "[SATP] ✗ Not connected" << std::endl;
            return false;
        }
        
        NavigationData processed_data = applyPrivacySettings(nav_data);
        SATPMessage msg = createMessage(MessageType::DATA, nav_data.urgency);
        msg.payload = serializeNavigationData(processed_data);
        
        return sendMessageUDP(msg);
    }
    
    bool sendData(const std::vector<uint8_t>& data, Priority priority = Priority::NORMAL) {
        if (!isConnected()) {
            std::cerr << "[SATP] ✗ Not connected" << std::endl;
            return false;
        }
        
        SATPMessage msg = createMessage(MessageType::DATA, priority);
        msg.payload = data;
        
        return sendMessageUDP(msg);
    }
    
    bool sendHeartbeat() {
        if (!isConnected()) {
            return false;
        }
        
        SATPMessage msg = createMessage(MessageType::HEARTBEAT, Priority::LOW);
        return sendMessageUDP(msg);
    }
    
    // ========================================================================
    // POWER MANAGEMENT
    // ========================================================================
    
    void updateBatteryLevel(uint8_t percentage) {
        device_info_.battery_percentage = percentage;
        
        PowerState old_state = device_info_.power_state;
        device_info_.power_state = determinePowerState(percentage);
        
        if (old_state != device_info_.power_state) {
            std::cout << "[SATP] Power state: " 
                      << powerStateToString(old_state) << " → " 
                      << powerStateToString(device_info_.power_state) << std::endl;
            
            SecurityLevel new_level = determineSecurityLevel();
            encryption_.updateSecurityLevel(new_level);
            
            std::cout << "[SATP] Security adapted: " 
                      << securityLevelToString(new_level) << std::endl;
            
            logSecurityEvent("SECURITY_ADAPTATION", 
                           "Security level adjusted for power state", false);
        }
    }
    
    // ========================================================================
    // STATUS & MONITORING
    // ========================================================================
    
    bool isConnected() const {
        return state_ == ConnectionState::CONNECTED;
    }
    
    void printStatistics() const {
        std::cout << "\n[SATP] ═══ NETWORK STATISTICS ═══" << std::endl;
        std::cout << "[SATP] Device ID: " << device_info_.device_id << std::endl;
        std::cout << "[SATP] Session ID: 0x" << std::hex << session_info_.session_id 
                  << std::dec << std::endl;
        std::cout << "[SATP] State: " << connectionStateToString(state_) << std::endl;
        std::cout << "[SATP] Security: " 
                  << securityLevelToString(encryption_.getSecurityLevel()) << std::endl;
        std::cout << "[SATP] Battery: " << (int)device_info_.battery_percentage << "%" << std::endl;
        std::cout << "[SATP] Messages Sent: " << messages_sent_ << std::endl;
        std::cout << "[SATP] Messages Received: " << messages_received_ << std::endl;
        std::cout << "[SATP] Bytes Sent: " << bytes_sent_ << " bytes" << std::endl;
        std::cout << "[SATP] Bytes Received: " << bytes_received_ << " bytes" << std::endl;
        std::cout << "[SATP] Errors: " << errors_ << std::endl;
        std::cout << "[SATP] ═══════════════════════════\n" << std::endl;
    }
    
    void setPrivacySettings(const PrivacySettings& settings) {
        privacy_settings_ = settings;
    }
    
private:
    // ========================================================================
    // UDP NETWORK OPERATIONS
    // ========================================================================
    
    bool sendMessageUDP(SATPMessage& msg) {
        try {
            // Update payload length
            msg.header.payload_length = msg.payload.size();
            
            // Encrypt payload (except for HELLO and HELLO_ACK which are plaintext)
            MessageType msg_type = static_cast<MessageType>(msg.header.message_type);
            bool should_encrypt = (msg_type != MessageType::HELLO && 
                                  msg_type != MessageType::HELLO_ACK);
            
            if (!msg.payload.empty() && should_encrypt) {
                msg.payload = encryption_.encrypt(msg.payload);
            }
            
            // Calculate HMAC
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
            
            // Serialize message to packet
            std::vector<uint8_t> packet = serializeMessage(msg);
            
            // Send via UDP socket
            ssize_t sent = sendto(udp_socket_,
                                 packet.data(),
                                 packet.size(),
                                 0,
                                 (struct sockaddr*)&server_addr_,
                                 sizeof(server_addr_));
            
            if (sent < 0) {
                std::cerr << "[SATP-NET] ✗ UDP send failed: " 
                          << strerror(errno) << std::endl;
                errors_++;
                return false;
            }
            
            bytes_sent_ += sent;
            messages_sent_++;
            
            std::cout << "[SATP-NET] ↑ Sent " 
                      << messageTypeToString(static_cast<MessageType>(msg.header.message_type))
                      << " (seq: " << msg.header.sequence_number 
                      << ", " << sent << " bytes)" << std::endl;
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "[SATP-NET] ✗ Send error: " << e.what() << std::endl;
            errors_++;
            return false;
        }
    }
    
    bool receiveMessageUDP(SATPMessage& msg) {
        uint8_t buffer[2048];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        
        ssize_t received = recvfrom(udp_socket_,
                                   buffer,
                                   sizeof(buffer),
                                   0,
                                   (struct sockaddr*)&from_addr,
                                   &from_len);
        
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cerr << "[SATP-NET] ✗ Receive timeout" << std::endl;
            } else {
                std::cerr << "[SATP-NET] ✗ UDP receive failed: " 
                          << strerror(errno) << std::endl;
            }
            errors_++;
            return false;
        }
        
        bytes_received_ += received;
        messages_received_++;
        
        // Deserialize packet
        if (!deserializeMessage(buffer, received, msg)) {
            std::cerr << "[SATP-NET] ✗ Failed to deserialize message" << std::endl;
            errors_++;
            return false;
        }
        
        // Verify HMAC
        std::vector<uint8_t> hmac_data;
        hmac_data.insert(hmac_data.end(),
                        reinterpret_cast<uint8_t*>(&msg.header),
                        reinterpret_cast<uint8_t*>(&msg.header) + sizeof(MessageHeader));
        hmac_data.insert(hmac_data.end(),
                        reinterpret_cast<uint8_t*>(&msg.security_meta),
                        reinterpret_cast<uint8_t*>(&msg.security_meta) + sizeof(SecurityMetadata));
        hmac_data.insert(hmac_data.end(),
                        msg.payload.begin(), msg.payload.end());
        
        if (!encryption_.verifyHMAC(hmac_data, msg.hmac)) {
            std::cerr << "[SATP-NET] ✗ HMAC verification failed!" << std::endl;
            logSecurityEvent("HMAC_VERIFICATION_FAILED", 
                           "Message integrity check failed", true);
            errors_++;
            return false;
        }
        
        // Decrypt payload (except HELLO and HELLO_ACK which are plaintext)
        MessageType recv_type = static_cast<MessageType>(msg.header.message_type);
        bool should_decrypt = (recv_type != MessageType::HELLO && 
                              recv_type != MessageType::HELLO_ACK);
        
        if (!msg.payload.empty() && should_decrypt) {
            msg.payload = encryption_.decrypt(msg.payload);
        }
        
        std::cout << "[SATP-NET] ↓ Received " 
                  << messageTypeToString(static_cast<MessageType>(msg.header.message_type))
                  << " (seq: " << msg.header.sequence_number 
                  << ", " << received << " bytes)" << std::endl;
        
        return true;
    }
    
    // Serialize message to byte array
    std::vector<uint8_t> serializeMessage(const SATPMessage& msg) {
        std::vector<uint8_t> packet;
        
        // Header
        packet.insert(packet.end(),
                     reinterpret_cast<const uint8_t*>(&msg.header),
                     reinterpret_cast<const uint8_t*>(&msg.header) + sizeof(MessageHeader));
        
        // Security metadata
        packet.insert(packet.end(),
                     reinterpret_cast<const uint8_t*>(&msg.security_meta),
                     reinterpret_cast<const uint8_t*>(&msg.security_meta) + sizeof(SecurityMetadata));
        
        // Payload
        packet.insert(packet.end(), msg.payload.begin(), msg.payload.end());
        
        // HMAC
        packet.insert(packet.end(), msg.hmac, msg.hmac + HMAC_SIZE);
        
        return packet;
    }
    
    // Deserialize byte array to message
    bool deserializeMessage(const uint8_t* buffer, size_t len, SATPMessage& msg) {
        if (len < HEADER_SIZE + SECURITY_METADATA_SIZE + HMAC_SIZE) {
            return false;
        }
        
        size_t offset = 0;
        
        // Header
        std::memcpy(&msg.header, buffer + offset, sizeof(MessageHeader));
        offset += sizeof(MessageHeader);
        
        // Security metadata
        std::memcpy(&msg.security_meta, buffer + offset, sizeof(SecurityMetadata));
        offset += sizeof(SecurityMetadata);
        
        // Payload
        size_t payload_size = len - offset - HMAC_SIZE;
        msg.payload.resize(payload_size);
        std::memcpy(msg.payload.data(), buffer + offset, payload_size);
        offset += payload_size;
        
        // HMAC
        std::memcpy(msg.hmac, buffer + offset, HMAC_SIZE);
        
        return true;
    }
    
    // ========================================================================
    // HELPER METHODS
    // ========================================================================
    
    SATPMessage createMessage(MessageType type, Priority priority) {
        SATPMessage msg;
        
        msg.header.version = SATP_VERSION;
        msg.header.message_type = static_cast<uint8_t>(type);
        msg.header.security_level = static_cast<uint8_t>(encryption_.getSecurityLevel());
        msg.header.priority = static_cast<uint8_t>(priority);
        msg.header.sequence_number = sequence_number_++;
        msg.header.payload_length = 0;
        msg.header.flags = 0;
        
        msg.security_meta.session_id = session_info_.session_id;
        msg.security_meta.timestamp = getCurrentTimestamp();
        
        return msg;
    }
    
    SecurityLevel determineSecurityLevel() const {
        switch (device_info_.power_state) {
            case PowerState::FULL: return SecurityLevel::LEVEL_1_MAXIMUM;
            case PowerState::BALANCED: return SecurityLevel::LEVEL_2_BALANCED;
            case PowerState::LOW: return SecurityLevel::LEVEL_3_MINIMAL;
            case PowerState::EMERGENCY: return SecurityLevel::LEVEL_EMERGENCY;
            default: return SecurityLevel::LEVEL_2_BALANCED;
        }
    }
    
    PowerState determinePowerState(uint8_t battery_percent) const {
        if (battery_percent > 70) return PowerState::FULL;
        if (battery_percent > 30) return PowerState::BALANCED;
        if (battery_percent > 10) return PowerState::LOW;
        return PowerState::EMERGENCY;
    }
    
    NavigationData applyPrivacySettings(const NavigationData& data) const {
        NavigationData processed = data;
        
        if (privacy_settings_.enable_location_anonymization) {
            double precision = privacy_settings_.location_precision_meters / 111000.0;
            processed.latitude = std::round(data.latitude / precision) * precision;
            processed.longitude = std::round(data.longitude / precision) * precision;
        }
        
        return processed;
    }
    
    std::vector<uint8_t> serializeNavigationData(const NavigationData& data) const {
        std::string serialized = std::to_string(data.latitude) + "," +
                                std::to_string(data.longitude) + "," +
                                std::to_string(data.heading) + "," +
                                std::to_string(data.distance_to_obstacle) + "," +
                                data.obstacle_type;
        
        return std::vector<uint8_t>(serialized.begin(), serialized.end());
    }
    
    uint64_t getCurrentTimestamp() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
    
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
            std::cerr << "[SATP] ⚠ CRITICAL: " << description << std::endl;
        }
    }
    
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
            case SecurityLevel::LEVEL_1_MAXIMUM: return "MAXIMUM";
            case SecurityLevel::LEVEL_2_BALANCED: return "BALANCED";
            case SecurityLevel::LEVEL_3_MINIMAL: return "MINIMAL";
            case SecurityLevel::LEVEL_EMERGENCY: return "EMERGENCY";
            default: return "UNKNOWN";
        }
    }
    
    std::string powerStateToString(PowerState state) const {
        switch (state) {
            case PowerState::FULL: return "FULL";
            case PowerState::BALANCED: return "BALANCED";
            case PowerState::LOW: return "LOW";
            case PowerState::EMERGENCY: return "EMERGENCY";
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

#endif // SATP_NETWORK_CLIENT_H
