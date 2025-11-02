#include "satp_client.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace SATP;

// ============================================================================
// DEMONSTRATION SCENARIOS
// ============================================================================

// Scenario 1: Normal navigation with full battery
void scenario1_NormalNavigation() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  SCENARIO 1: Normal Navigation with Full Battery          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    // Create smart cane device
    SATPClient smart_cane("CANE_001", "smart_cane");
    
    // Set privacy settings
    PrivacySettings privacy;
    privacy.enable_location_anonymization = true;
    privacy.prefer_local_processing = true;
    privacy.location_precision_meters = 50;
    smart_cane.setPrivacySettings(privacy);
    
    // Connect to navigation server
    if (!smart_cane.connect()) {
        std::cerr << "Failed to connect!" << std::endl;
        return;
    }
    
    // Simulate navigation sequence
    std::cout << "\n[DEMO] Starting navigation session..." << std::endl;
    
    // Send location updates
    for (int i = 0; i < 3; i++) {
        NavigationData nav_data;
        nav_data.latitude = 51.1605 + i * 0.0001;  // Simulated movement
        nav_data.longitude = 71.4704 + i * 0.0001;
        nav_data.heading = 45.0f + i * 10.0f;
        nav_data.distance_to_obstacle = -1.0f;  // No obstacle
        nav_data.urgency = Priority::NORMAL;
        
        std::cout << "\n[DEMO] Sending location update #" << (i+1) << std::endl;
        smart_cane.sendNavigationData(nav_data);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    // Obstacle detected!
    std::cout << "\n[DEMO] ⚠ OBSTACLE DETECTED!" << std::endl;
    NavigationData obstacle_data;
    obstacle_data.latitude = 51.1608;
    obstacle_data.longitude = 71.4707;
    obstacle_data.heading = 75.0f;
    obstacle_data.distance_to_obstacle = 2.0f;  // 2 meters ahead
    obstacle_data.obstacle_type = "pedestrian";
    obstacle_data.urgency = Priority::HIGH;
    
    smart_cane.sendNavigationData(obstacle_data);
    
    // Send heartbeat
    std::cout << "\n[DEMO] Sending heartbeat..." << std::endl;
    smart_cane.sendHeartbeat();
    
    // Show statistics
    smart_cane.printStatistics();
    
    // Disconnect
    smart_cane.disconnect();
}

// Scenario 2: Battery drain and security adaptation
void scenario2_BatteryDrainAdaptation() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  SCENARIO 2: Battery Drain & Security Adaptation          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    SATPClient wearable("WEAR_042", "wearable_sensor");
    
    // Connect with full battery
    std::cout << "[DEMO] Connecting with 100% battery..." << std::endl;
    if (!wearable.connect()) {
        return;
    }
    
    // Simulate battery drain over time
    uint8_t battery_levels[] = {100, 75, 50, 25, 15, 8};
    
    for (uint8_t level : battery_levels) {
        std::cout << "\n[DEMO] Battery level: " << (int)level << "%" << std::endl;
        wearable.updateBatteryLevel(level);
        
        // Send test data
        NavigationData data;
        data.latitude = 51.1605;
        data.longitude = 71.4704;
        data.urgency = Priority::NORMAL;
        
        wearable.sendNavigationData(data);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    
    std::cout << "\n[DEMO] Notice how security level adapts to power state!" << std::endl;
    wearable.printStatistics();
    
    wearable.disconnect();
}

// Scenario 3: Privacy-aware location sharing
void scenario3_PrivacyAwareLocation() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  SCENARIO 3: Privacy-Aware Location Sharing               ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    SATPClient device("DEV_099", "navigation_aid");
    
    // Configure privacy settings
    std::cout << "[DEMO] Configuring privacy settings..." << std::endl;
    PrivacySettings privacy;
    privacy.enable_location_anonymization = true;
    privacy.prefer_local_processing = true;
    privacy.enable_cloud_routing = false;  // Avoid cloud for privacy
    privacy.location_precision_meters = 100;  // Reduce precision to 100m
    device.setPrivacySettings(privacy);
    
    std::cout << "[DEMO] Privacy Settings:" << std::endl;
    std::cout << "  - Location anonymization: ENABLED" << std::endl;
    std::cout << "  - Local processing preferred: YES" << std::endl;
    std::cout << "  - Cloud routing: DISABLED" << std::endl;
    std::cout << "  - Location precision: 100 meters" << std::endl;
    
    device.connect();
    
    // Send precise location
    NavigationData precise;
    precise.latitude = 51.16053742;
    precise.longitude = 71.47042156;
    precise.heading = 90.0f;
    precise.urgency = Priority::NORMAL;
    
    std::cout << "\n[DEMO] Original location:" << std::endl;
    std::cout << "  Lat: " << precise.latitude << ", Lon: " << precise.longitude << std::endl;
    std::cout << "\n[DEMO] After privacy anonymization, precision reduced to 100m" << std::endl;
    std::cout << "[DEMO] This protects user privacy while maintaining functionality" << std::endl;
    
    device.sendNavigationData(precise);
    
    device.printStatistics();
    device.disconnect();
}

// Scenario 4: Critical safety alert
void scenario4_CriticalSafetyAlert() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  SCENARIO 4: Critical Safety Alert                        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    SATPClient device("SAFE_007", "smart_cane");
    device.connect();
    
    std::cout << "[DEMO] User is walking normally..." << std::endl;
    
    // Normal navigation
    NavigationData normal;
    normal.latitude = 51.1605;
    normal.longitude = 71.4704;
    normal.heading = 0.0f;
    normal.distance_to_obstacle = -1.0f;
    normal.urgency = Priority::NORMAL;
    device.sendNavigationData(normal);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // CRITICAL: Obstacle detected very close!
    std::cout << "\n[DEMO] 🚨 CRITICAL SAFETY ALERT! 🚨" << std::endl;
    std::cout << "[DEMO] Obstacle detected at 0.5 meters!" << std::endl;
    
    NavigationData critical;
    critical.latitude = 51.1606;
    critical.longitude = 71.4705;
    critical.heading = 0.0f;
    critical.distance_to_obstacle = 0.5f;  // Very close!
    critical.obstacle_type = "vehicle";
    critical.urgency = Priority::CRITICAL;
    
    // This message will be sent with highest priority
    // ensuring minimum latency for safety
    device.sendNavigationData(critical);
    
    std::cout << "[DEMO] Critical message sent with highest priority" << std::endl;
    std::cout << "[DEMO] User receives immediate audio warning" << std::endl;
    
    device.printStatistics();
    device.disconnect();
}

// Scenario 5: Security event monitoring
void scenario5_SecurityMonitoring() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  SCENARIO 5: Security Event Monitoring                    ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    SATPClient device("MON_123", "monitoring_device");
    device.connect();
    
    // Perform various operations
    std::cout << "[DEMO] Performing secure operations..." << std::endl;
    
    for (int i = 0; i < 5; i++) {
        NavigationData data;
        data.latitude = 51.16 + i * 0.0001;
        data.longitude = 71.47 + i * 0.0001;
        data.urgency = Priority::NORMAL;
        device.sendNavigationData(data);
    }
    
    // Simulate battery changes (triggers security events)
    device.updateBatteryLevel(45);
    device.updateBatteryLevel(20);
    
    // Show security log
    std::cout << "\n[DEMO] Security Event Log:" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════" << std::endl;
    
    const auto& log = device.getSecurityLog();
    for (const auto& event : log) {
        auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
        std::cout << "  [" << std::ctime(&time_t);
        std::cout << "  Type: " << event.event_type << std::endl;
        std::cout << "  Description: " << event.description << std::endl;
        std::cout << "  Critical: " << (event.is_critical ? "YES" : "NO") << std::endl;
        std::cout << "  ───────────────────────────────────────────────────────" << std::endl;
    }
    
    device.printStatistics();
    device.disconnect();
}

// ============================================================================
// MAIN DEMONSTRATION
// ============================================================================

int main() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    SATP: Secure Assistive Transport Protocol                        ║
║    Research Prototype Demonstration                                 ║
║                                                                      ║
║    Authors: Aitkazy B., Bekbulat A., Baktash A.P.,                 ║
║             Kurmanbekov A., Turtulov R.                             ║
║    Course: MIIL 3222 - Research Methods and Tools                   ║
║    Institution: Astana IT University                                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;

    std::cout << "\nThis prototype demonstrates the key features of SATP:\n" << std::endl;
    std::cout << "  ✓ Mandatory end-to-end encryption" << std::endl;
    std::cout << "  ✓ Power-aware security adaptation" << std::endl;
    std::cout << "  ✓ Privacy-by-design architecture" << std::endl;
    std::cout << "  ✓ Safety-critical message handling" << std::endl;
    std::cout << "  ✓ Real-time performance for navigation" << std::endl;
    
    std::cout << "\n[INFO] Note: This is a research prototype simulating cryptographic" << std::endl;
    std::cout << "[INFO] operations. Production implementation would use OpenSSL/BoringSSL." << std::endl;
    
    std::cout << "\nPress Enter to start demonstrations..." << std::endl;
    std::cin.get();
    
    // Run all scenarios
    scenario1_NormalNavigation();
    
    std::cout << "\nPress Enter for next scenario..." << std::endl;
    std::cin.get();
    
    scenario2_BatteryDrainAdaptation();
    
    std::cout << "\nPress Enter for next scenario..." << std::endl;
    std::cin.get();
    
    scenario3_PrivacyAwareLocation();
    
    std::cout << "\nPress Enter for next scenario..." << std::endl;
    std::cin.get();
    
    scenario4_CriticalSafetyAlert();
    
    std::cout << "\nPress Enter for next scenario..." << std::endl;
    std::cin.get();
    
    scenario5_SecurityMonitoring();
    
    // Final summary
    std::cout << "\n╔══════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                    DEMONSTRATION COMPLETE                        ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    std::cout << "SATP Protocol Key Achievements:\n" << std::endl;
    std::cout << "1. Addresses vulnerabilities in MQTT, CoAP, BLE identified by experts" << std::endl;
    std::cout << "2. Implements privacy-by-design for vulnerable users" << std::endl;
    std::cout << "3. Balances security with power efficiency" << std::endl;
    std::cout << "4. Prioritizes safety-critical navigation messages" << std::endl;
    std::cout << "5. Provides adaptive security based on device state" << std::endl;
    
    std::cout << "\nFor complete protocol specification, see: SATP_Protocol_Design.md" << std::endl;
    std::cout << "\nThank you for reviewing our research prototype!" << std::endl;
    
    return 0;
}
