#ifndef SATP_PROTOCOL_H
#define SATP_PROTOCOL_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <memory>

namespace SATP {

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

constexpr uint8_t SATP_VERSION = 1;
constexpr size_t MAX_PAYLOAD_SIZE = 1024;
constexpr size_t HEADER_SIZE = 8;
constexpr size_t SECURITY_METADATA_SIZE = 16;
constexpr size_t HMAC_SIZE = 32;
constexpr size_t TOTAL_OVERHEAD = HEADER_SIZE + SECURITY_METADATA_SIZE + HMAC_SIZE;

// ============================================================================
// ENUMERATIONS
// ============================================================================

// Message types
enum class MessageType : uint8_t {
    HELLO = 0x01,
    HELLO_ACK = 0x02,
    KEY_EXCHANGE = 0x03,
    SESSION_READY = 0x04,
    DATA = 0x05,
    HEARTBEAT = 0x06,
    DISCONNECT = 0x07,
    ALERT = 0x08
};

// Security levels (adaptive based on power and threat)
enum class SecurityLevel : uint8_t {
    LEVEL_1_MAXIMUM = 0x00,  // Full DTLS 1.3, certificate auth
    LEVEL_2_BALANCED = 0x01,  // AES-128-GCM, PSK auth (default)
    LEVEL_3_MINIMAL = 0x02,   // Lightweight encryption
    LEVEL_EMERGENCY = 0x03    // Critical commands only
};

// Message priority
enum class Priority : uint8_t {
    LOW = 0x00,      // Non-critical telemetry
    NORMAL = 0x01,   // Regular data
    HIGH = 0x02,     // Important navigation data
    CRITICAL = 0x03  // Safety-critical commands
};

// Power states
enum class PowerState : uint8_t {
    FULL = 0,        // >70% battery
    BALANCED = 1,    // 30-70% battery
    LOW = 2,         // 10-30% battery
    EMERGENCY = 3    // <10% battery
};

// Connection state
enum class ConnectionState {
    DISCONNECTED,
    INITIATING,
    HANDSHAKING,
    CONNECTED,
    ERROR
};

// ============================================================================
// PROTOCOL STRUCTURES
// ============================================================================

// Message Header (8 bytes)
struct MessageHeader {
    uint8_t version : 4;           // Protocol version
    uint8_t message_type : 4;      // MessageType enum
    uint8_t security_level : 2;    // SecurityLevel enum
    uint8_t priority : 2;          // Priority enum
    uint8_t reserved : 4;          // Reserved for future use
    uint16_t sequence_number;      // Sequence number for ordering
    uint16_t payload_length;       // Length of payload in bytes
    uint16_t flags;                // Additional flags
} __attribute__((packed));

// Security Metadata (16 bytes)
struct SecurityMetadata {
    uint64_t session_id;           // Unique session identifier
    uint64_t timestamp;            // Unix timestamp in milliseconds
} __attribute__((packed));

// Complete SATP Message
struct SATPMessage {
    MessageHeader header;
    SecurityMetadata security_meta;
    std::vector<uint8_t> payload;
    uint8_t hmac[HMAC_SIZE];       // HMAC-SHA256 integrity check
    
    SATPMessage() {
        std::memset(&header, 0, sizeof(MessageHeader));
        std::memset(&security_meta, 0, sizeof(SecurityMetadata));
        std::memset(hmac, 0, HMAC_SIZE);
    }
};

// Session Information
struct SessionInfo {
    uint64_t session_id;
    SecurityLevel security_level;
    std::vector<uint8_t> session_key;
    std::chrono::system_clock::time_point created_at;
    bool is_authenticated;
    
    SessionInfo() : session_id(0), 
                   security_level(SecurityLevel::LEVEL_2_BALANCED),
                   is_authenticated(false) {
        created_at = std::chrono::system_clock::now();
    }
};

// Device Information
struct DeviceInfo {
    std::string device_id;
    std::string device_type;      // e.g., "smart_cane", "wearable"
    PowerState power_state;
    uint8_t battery_percentage;
    bool is_assistive_device;     // Flag for accessibility features
    
    DeviceInfo() : power_state(PowerState::FULL), 
                   battery_percentage(100),
                   is_assistive_device(true) {}
};

// Navigation Data (example payload structure)
struct NavigationData {
    double latitude;
    double longitude;
    float heading;                 // Degrees from north
    float distance_to_obstacle;    // Meters
    std::string obstacle_type;
    Priority urgency;
    
    NavigationData() : latitude(0.0), longitude(0.0), 
                      heading(0.0), distance_to_obstacle(-1.0),
                      urgency(Priority::NORMAL) {}
};

// Security Event Log Entry
struct SecurityEvent {
    std::chrono::system_clock::time_point timestamp;
    std::string event_type;
    std::string description;
    SecurityLevel security_level;
    bool is_critical;
};

// Privacy Settings
struct PrivacySettings {
    bool enable_location_anonymization;
    bool prefer_local_processing;
    bool enable_cloud_routing;
    uint8_t location_precision_meters;  // Minimum: 10m, Maximum: 1000m
    
    PrivacySettings() : enable_location_anonymization(true),
                       prefer_local_processing(true),
                       enable_cloud_routing(false),
                       location_precision_meters(50) {}
};

} // namespace SATP

#endif // SATP_PROTOCOL_H
