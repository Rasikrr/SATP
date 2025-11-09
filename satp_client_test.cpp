#include "satp_network_client.h"
#include <iostream>
#include <thread>
#include <chrono>

using namespace SATP;

int main(int argc, char* argv[]) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    SATP Network Client - Real UDP Implementation                    ║
║    Secure Assistive Transport Protocol                              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;

    // Parse server address and port
    std::string server_ip = "127.0.0.1";  // localhost by default
    uint16_t port = 5555;
    
    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        port = std::atoi(argv[2]);
    }
    
    std::cout << "[INFO] Server address: " << server_ip << ":" << port << "\n" << std::endl;
    
    // Create client
    SATPNetworkClient client("SMART_CANE_001", "smart_cane");
    
    // Configure privacy settings
    PrivacySettings privacy;
    privacy.enable_location_anonymization = true;
    privacy.prefer_local_processing = true;
    privacy.location_precision_meters = 50;
    client.setPrivacySettings(privacy);
    
    // Initialize network
    if (!client.initializeSocket(server_ip, port)) {
        std::cerr << "[ERROR] Failed to initialize socket" << std::endl;
        return 1;
    }
    
    // Connect to server
    if (!client.connect()) {
        std::cerr << "[ERROR] Failed to connect to server" << std::endl;
        return 1;
    }
    
    std::cout << "\n[TEST] Starting data transmission tests...\n" << std::endl;
    
    // Test 1: Send navigation data
    std::cout << "═══ Test 1: Sending Navigation Data ═══" << std::endl;
    for (int i = 0; i < 3; i++) {
        NavigationData nav;
        nav.latitude = 51.1605 + i * 0.0001;
        nav.longitude = 71.4704 + i * 0.0001;
        nav.heading = 45.0f + i * 15.0f;
        nav.distance_to_obstacle = -1.0f;
        nav.urgency = Priority::NORMAL;
        
        std::cout << "\n[TEST] Sending location update #" << (i+1) << std::endl;
        std::cout << "  Lat: " << nav.latitude << ", Lon: " << nav.longitude << std::endl;
        
        if (client.sendNavigationData(nav)) {
            std::cout << "  ✓ Sent successfully" << std::endl;
        } else {
            std::cerr << "  ✗ Failed to send" << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    // Test 2: Send obstacle alert (HIGH priority)
    std::cout << "\n═══ Test 2: Sending Critical Obstacle Alert ═══" << std::endl;
    NavigationData obstacle;
    obstacle.latitude = 51.1608;
    obstacle.longitude = 71.4707;
    obstacle.heading = 75.0f;
    obstacle.distance_to_obstacle = 1.5f;
    obstacle.obstacle_type = "pedestrian";
    obstacle.urgency = Priority::CRITICAL;
    
    std::cout << "[TEST] ⚠ CRITICAL: Obstacle at 1.5 meters!" << std::endl;
    if (client.sendNavigationData(obstacle)) {
        std::cout << "  ✓ Critical alert sent" << std::endl;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Test 3: Send custom data
    std::cout << "\n═══ Test 3: Sending Custom Data ═══" << std::endl;
    std::string custom_message = "Hello from Smart Cane! Battery OK, all sensors operational.";
    std::vector<uint8_t> custom_data(custom_message.begin(), custom_message.end());
    
    std::cout << "[TEST] Sending: \"" << custom_message << "\"" << std::endl;
    if (client.sendData(custom_data, Priority::NORMAL)) {
        std::cout << "  ✓ Custom data sent" << std::endl;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Test 4: Heartbeat
    std::cout << "\n═══ Test 4: Sending Heartbeat ═══" << std::endl;
    if (client.sendHeartbeat()) {
        std::cout << "  ✓ Heartbeat sent" << std::endl;
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Test 5: Battery adaptation
    std::cout << "\n═══ Test 5: Testing Power-Aware Security ═══" << std::endl;
    std::cout << "[TEST] Simulating battery drain..." << std::endl;
    
    uint8_t battery_levels[] = {65, 40, 15};
    for (uint8_t level : battery_levels) {
        std::cout << "\n[TEST] Battery: " << (int)level << "%" << std::endl;
        client.updateBatteryLevel(level);
        
        // Send data to test adapted security level
        NavigationData test_nav;
        test_nav.latitude = 51.16;
        test_nav.longitude = 71.47;
        test_nav.urgency = Priority::NORMAL;
        client.sendNavigationData(test_nav);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    // Print statistics
    std::cout << "\n═══ Final Statistics ═══" << std::endl;
    client.printStatistics();
    
    // Disconnect
    std::cout << "[TEST] Disconnecting from server..." << std::endl;
    client.disconnect();
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              SATP Network Test Completed Successfully            ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════════╝\n" << std::endl;
    
    return 0;
}
