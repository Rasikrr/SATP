#ifndef SATP_NETWORK_SERVER_H
#define SATP_NETWORK_SERVER_H

#include "satp_protocol.h"
#include "satp_encryption.h"
#include <iostream>
#include <vector>
#include <map>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

namespace SATP {

// ============================================================================
// SATP NETWORK SERVER (Real UDP Implementation)
// ============================================================================
// Server implementation with actual UDP socket communication

class SATPNetworkServer {
private:
    // Network components
    int udp_socket_;
    struct sockaddr_in server_addr_;
    uint16_t port_;
    bool is_running_;
    
    // Client sessions
    struct ClientSession {
        struct sockaddr_in addr;
        uint64_t session_id;
        EncryptionManager encryption;
        bool is_authenticated;
        std::chrono::system_clock::time_point last_seen;
        std::string device_id;
        uint16_t last_sequence;
    };
    
    std::map<std::string, ClientSession> clients_;  // Key: IP:Port
    
    // Statistics
    size_t messages_received_;
    size_t messages_sent_;
    size_t active_sessions_;
    size_t bytes_received_;
    size_t bytes_sent_;
    
public:
    SATPNetworkServer(uint16_t port = 5555) 
        : udp_socket_(-1),
          port_(port),
          is_running_(false),
          messages_received_(0),
          messages_sent_(0),
          active_sessions_(0),
          bytes_received_(0),
          bytes_sent_(0) {
        memset(&server_addr_, 0, sizeof(server_addr_));
    }
    
    ~SATPNetworkServer() {
        stop();
    }
    
    // ========================================================================
    // SERVER CONTROL
    // ========================================================================
    
    bool start() {
        std::cout << "\n[SATP-SERVER] ═══════════════════════════════" << std::endl;
        std::cout << "[SATP-SERVER] Starting SATP Server..." << std::endl;
        std::cout << "[SATP-SERVER] ═══════════════════════════════\n" << std::endl;
        
        // Create UDP socket
        udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket_ < 0) {
            std::cerr << "[SATP-SERVER] ✗ Failed to create socket: " 
                      << strerror(errno) << std::endl;
            return false;
        }
        
        // Allow socket reuse
        int opt = 1;
        setsockopt(udp_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        // Configure server address
        server_addr_.sin_family = AF_INET;
        server_addr_.sin_addr.s_addr = INADDR_ANY;
        server_addr_.sin_port = htons(port_);
        
        // Bind socket
        if (bind(udp_socket_, (struct sockaddr*)&server_addr_, sizeof(server_addr_)) < 0) {
            std::cerr << "[SATP-SERVER] ✗ Bind failed: " 
                      << strerror(errno) << std::endl;
            close(udp_socket_);
            return false;
        }
        
        is_running_ = true;
        
        std::cout << "[SATP-SERVER] ✓ Server started successfully" << std::endl;
        std::cout << "[SATP-SERVER] Listening on port: " << port_ << std::endl;
        std::cout << "[SATP-SERVER] Transport: UDP" << std::endl;
        std::cout << "[SATP-SERVER] Waiting for clients...\n" << std::endl;
        
        return true;
    }
    
    void stop() {
        if (is_running_) {
            is_running_ = false;
            if (udp_socket_ >= 0) {
                close(udp_socket_);
                udp_socket_ = -1;
            }
            std::cout << "[SATP-SERVER] Server stopped" << std::endl;
        }
    }
    
    // ========================================================================
    // MESSAGE HANDLING
    // ========================================================================
    
    void run() {
        if (!is_running_) {
            std::cerr << "[SATP-SERVER] Server not started" << std::endl;
            return;
        }
        
        std::cout << "[SATP-SERVER] Server running. Press Ctrl+C to stop.\n" << std::endl;
        
        uint8_t buffer[2048];
        
        while (is_running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            // Receive message
            ssize_t received = recvfrom(udp_socket_,
                                       buffer,
                                       sizeof(buffer),
                                       0,
                                       (struct sockaddr*)&client_addr,
                                       &client_len);
            
            if (received < 0) {
                if (errno == EINTR) break;  // Interrupted
                std::cerr << "[SATP-SERVER] Receive error: " 
                          << strerror(errno) << std::endl;
                continue;
            }
            
            bytes_received_ += received;
            messages_received_++;
            
            // Get client key
            std::string client_key = getClientKey(client_addr);
            
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            
            std::cout << "[SATP-SERVER] ↓ Received " << received 
                      << " bytes from " << client_ip << ":" 
                      << ntohs(client_addr.sin_port) << std::endl;
            
            // Deserialize message
            SATPMessage msg;
            if (!deserializeMessage(buffer, received, msg)) {
                std::cerr << "[SATP-SERVER] ✗ Failed to deserialize" << std::endl;
                continue;
            }
            
            // Handle message
            handleMessage(msg, client_addr, client_key);
        }
    }
    
    void printStatistics() const {
        std::cout << "\n[SATP-SERVER] ═══ SERVER STATISTICS ═══" << std::endl;
        std::cout << "[SATP-SERVER] Port: " << port_ << std::endl;
        std::cout << "[SATP-SERVER] Active Sessions: " << clients_.size() << std::endl;
        std::cout << "[SATP-SERVER] Messages Received: " << messages_received_ << std::endl;
        std::cout << "[SATP-SERVER] Messages Sent: " << messages_sent_ << std::endl;
        std::cout << "[SATP-SERVER] Bytes Received: " << bytes_received_ << " bytes" << std::endl;
        std::cout << "[SATP-SERVER] Bytes Sent: " << bytes_sent_ << " bytes" << std::endl;
        std::cout << "[SATP-SERVER] ═══════════════════════════\n" << std::endl;
    }
    
private:
    // ========================================================================
    // MESSAGE PROCESSING
    // ========================================================================
    
    void handleMessage(SATPMessage& msg, const struct sockaddr_in& client_addr, 
                      const std::string& client_key) {
        MessageType msg_type = static_cast<MessageType>(msg.header.message_type);
        
        std::cout << "[SATP-SERVER] Processing: " 
                  << messageTypeToString(msg_type) 
                  << " (seq: " << msg.header.sequence_number << ")" << std::endl;
        
        switch (msg_type) {
            case MessageType::HELLO:
                handleHello(msg, client_addr, client_key);
                break;
                
            case MessageType::KEY_EXCHANGE:
                handleKeyExchange(msg, client_addr, client_key);
                break;
                
            case MessageType::DATA:
                handleData(msg, client_addr, client_key);
                break;
                
            case MessageType::HEARTBEAT:
                handleHeartbeat(msg, client_addr, client_key);
                break;
                
            case MessageType::DISCONNECT:
                handleDisconnect(msg, client_addr, client_key);
                break;
                
            default:
                std::cout << "[SATP-SERVER] Unknown message type" << std::endl;
        }
    }
    
    void handleHello(SATPMessage& msg, const struct sockaddr_in& client_addr,
                    const std::string& client_key) {
        std::cout << "[SATP-SERVER] → New client connection request" << std::endl;
        
        // Create new session
        ClientSession session;
        session.addr = client_addr;
        session.session_id = generateSessionID();
        session.is_authenticated = false;
        session.last_seen = std::chrono::system_clock::now();
        session.last_sequence = msg.header.sequence_number;
        
        // Extract device ID from payload
        if (!msg.payload.empty()) {
            std::string device_info(msg.payload.begin(), msg.payload.end());
            size_t colon_pos = device_info.find(':');
            if (colon_pos != std::string::npos) {
                session.device_id = device_info.substr(0, colon_pos);
            }
        }
        
        // Initialize encryption for this session with PSK
        // Match the client's security level from the message header
        SecurityLevel client_level = static_cast<SecurityLevel>(msg.header.security_level);
        std::string psk = "SATP_SECRET_KEY_2024_IoT_Assistive_Device";  // Same PSK as client
        session.encryption.initializeWithPSK(client_level, psk);
        
        // Store session
        clients_[client_key] = session;
        active_sessions_ = clients_.size();
        
        std::cout << "[SATP-SERVER] ✓ Session created for device: " 
                  << session.device_id << std::endl;
        std::cout << "[SATP-SERVER] Session ID: 0x" << std::hex 
                  << session.session_id << std::dec << std::endl;
        
        // Send HELLO_ACK
        SATPMessage ack;
        ack.header.version = SATP_VERSION;
        ack.header.message_type = static_cast<uint8_t>(MessageType::HELLO_ACK);
        ack.header.security_level = static_cast<uint8_t>(client_level);  // Match client level
        ack.header.priority = static_cast<uint8_t>(Priority::HIGH);
        ack.header.sequence_number = 0;
        ack.header.payload_length = 0;
        ack.header.flags = 0;
        
        ack.security_meta.session_id = session.session_id;
        ack.security_meta.timestamp = getCurrentTimestamp();
        
        sendMessage(ack, client_addr, session.encryption);
    }
    
    void handleKeyExchange(SATPMessage& msg, const struct sockaddr_in& client_addr,
                          const std::string& client_key) {
        auto it = clients_.find(client_key);
        if (it == clients_.end()) {
            std::cerr << "[SATP-SERVER] ✗ Session not found for KEY_EXCHANGE" << std::endl;
            return;
        }
        
        std::cout << "[SATP-SERVER] → Key exchange in progress" << std::endl;
        
        // Mark session as authenticated
        it->second.is_authenticated = true;
        it->second.last_seen = std::chrono::system_clock::now();
        
        // Send SESSION_READY
        SATPMessage ready;
        ready.header.version = SATP_VERSION;
        ready.header.message_type = static_cast<uint8_t>(MessageType::SESSION_READY);
        ready.header.security_level = static_cast<uint8_t>(it->second.encryption.getSecurityLevel());
        ready.header.priority = static_cast<uint8_t>(Priority::HIGH);
        ready.header.sequence_number = 1;
        ready.header.payload_length = 0;
        ready.header.flags = 0;
        
        ready.security_meta.session_id = it->second.session_id;
        ready.security_meta.timestamp = getCurrentTimestamp();
        
        sendMessage(ready, client_addr, it->second.encryption);
        
        std::cout << "[SATP-SERVER] ✓ Session authenticated: " 
                  << it->second.device_id << std::endl;
    }
    
    void handleData(SATPMessage& msg, const struct sockaddr_in& client_addr,
                   const std::string& client_key) {
        auto it = clients_.find(client_key);
        if (it == clients_.end() || !it->second.is_authenticated) {
            std::cerr << "[SATP-SERVER] ✗ Unauthorized DATA message" << std::endl;
            return;
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
        
        if (!it->second.encryption.verifyHMAC(hmac_data, msg.hmac)) {
            std::cerr << "[SATP-SERVER] ✗ HMAC verification failed!" << std::endl;
            return;
        }
        
        // Decrypt payload
        std::vector<uint8_t> plaintext;
        if (!msg.payload.empty()) {
            plaintext = it->second.encryption.decrypt(msg.payload);
        }
        
        it->second.last_seen = std::chrono::system_clock::now();
        it->second.last_sequence = msg.header.sequence_number;
        
        std::cout << "[SATP-SERVER] ✓ DATA from " << it->second.device_id 
                  << " (priority: " << (int)msg.header.priority 
                  << ", payload: " << plaintext.size() << " bytes)" << std::endl;
        
        // Print decrypted data
        if (!plaintext.empty() && plaintext.size() < 200) {
            std::string data_str(plaintext.begin(), plaintext.end());
            std::cout << "[SATP-SERVER] Decrypted data: " << data_str << std::endl;
        }
    }
    
    void handleHeartbeat(SATPMessage& msg, const struct sockaddr_in& client_addr,
                        const std::string& client_key) {
        auto it = clients_.find(client_key);
        if (it != clients_.end()) {
            it->second.last_seen = std::chrono::system_clock::now();
            std::cout << "[SATP-SERVER] ✓ Heartbeat from " 
                      << it->second.device_id << std::endl;
        }
    }
    
    void handleDisconnect(SATPMessage& msg, const struct sockaddr_in& client_addr,
                         const std::string& client_key) {
        auto it = clients_.find(client_key);
        if (it != clients_.end()) {
            std::cout << "[SATP-SERVER] Client disconnected: " 
                      << it->second.device_id << std::endl;
            clients_.erase(it);
            active_sessions_ = clients_.size();
        }
    }
    
    // ========================================================================
    // NETWORK OPERATIONS
    // ========================================================================
    
    bool sendMessage(SATPMessage& msg, const struct sockaddr_in& client_addr,
                    EncryptionManager& encryption) {
        try {
            // Update payload length
            msg.header.payload_length = msg.payload.size();
            
            // Encrypt payload (except HELLO and HELLO_ACK which are plaintext)
            MessageType msg_type = static_cast<MessageType>(msg.header.message_type);
            bool should_encrypt = (msg_type != MessageType::HELLO && 
                                  msg_type != MessageType::HELLO_ACK);
            
            if (!msg.payload.empty() && should_encrypt) {
                msg.payload = encryption.encrypt(msg.payload);
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
            
            auto hmac_result = encryption.calculateHMAC(hmac_data);
            std::memcpy(msg.hmac, hmac_result.data(), HMAC_SIZE);
            
            // Serialize
            std::vector<uint8_t> packet = serializeMessage(msg);
            
            // Send
            ssize_t sent = sendto(udp_socket_,
                                 packet.data(),
                                 packet.size(),
                                 0,
                                 (struct sockaddr*)&client_addr,
                                 sizeof(client_addr));
            
            if (sent < 0) {
                std::cerr << "[SATP-SERVER] ✗ Send failed: " 
                          << strerror(errno) << std::endl;
                return false;
            }
            
            bytes_sent_ += sent;
            messages_sent_++;
            
            std::cout << "[SATP-SERVER] ↑ Sent " 
                      << messageTypeToString(static_cast<MessageType>(msg.header.message_type))
                      << " (" << sent << " bytes)" << std::endl;
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "[SATP-SERVER] ✗ Send error: " << e.what() << std::endl;
            return false;
        }
    }
    
    std::vector<uint8_t> serializeMessage(const SATPMessage& msg) {
        std::vector<uint8_t> packet;
        
        packet.insert(packet.end(),
                     reinterpret_cast<const uint8_t*>(&msg.header),
                     reinterpret_cast<const uint8_t*>(&msg.header) + sizeof(MessageHeader));
        
        packet.insert(packet.end(),
                     reinterpret_cast<const uint8_t*>(&msg.security_meta),
                     reinterpret_cast<const uint8_t*>(&msg.security_meta) + sizeof(SecurityMetadata));
        
        packet.insert(packet.end(), msg.payload.begin(), msg.payload.end());
        
        packet.insert(packet.end(), msg.hmac, msg.hmac + HMAC_SIZE);
        
        return packet;
    }
    
    bool deserializeMessage(const uint8_t* buffer, size_t len, SATPMessage& msg) {
        if (len < HEADER_SIZE + SECURITY_METADATA_SIZE + HMAC_SIZE) {
            return false;
        }
        
        size_t offset = 0;
        
        std::memcpy(&msg.header, buffer + offset, sizeof(MessageHeader));
        offset += sizeof(MessageHeader);
        
        std::memcpy(&msg.security_meta, buffer + offset, sizeof(SecurityMetadata));
        offset += sizeof(SecurityMetadata);
        
        size_t payload_size = len - offset - HMAC_SIZE;
        msg.payload.resize(payload_size);
        std::memcpy(msg.payload.data(), buffer + offset, payload_size);
        offset += payload_size;
        
        std::memcpy(msg.hmac, buffer + offset, HMAC_SIZE);
        
        return true;
    }
    
    // ========================================================================
    // HELPER METHODS
    // ========================================================================
    
    std::string getClientKey(const struct sockaddr_in& addr) const {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
    }
    
    uint64_t generateSessionID() const {
        return std::chrono::system_clock::now().time_since_epoch().count();
    }
    
    uint64_t getCurrentTimestamp() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
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
};

} // namespace SATP

#endif // SATP_NETWORK_SERVER_H
