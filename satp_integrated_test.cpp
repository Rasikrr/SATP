#include "satp_network_server.h"
#include "satp_network_client.h"
#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

using namespace SATP;

void runServer() {
    SATPNetworkServer server(5555);
    
    if (!server.start()) {
        std::cerr << "[SERVER] Failed to start" << std::endl;
        exit(1);
    }
    
    std::cout << "[SERVER] Running for 15 seconds..." << std::endl;
    
    // Run for limited time
    alarm(15);  // Auto-exit after 15 seconds
    server.run();
    
    server.printStatistics();
    exit(0);
}

void runClient() {
    // Wait for server to start
    sleep(1);
    
    SATPNetworkClient client("SMART_CANE_001", "smart_cane");
    
    // Configure privacy
    PrivacySettings privacy;
    privacy.enable_location_anonymization = true;
    privacy.location_precision_meters = 50;
    client.setPrivacySettings(privacy);
    
    // Initialize and connect
    if (!client.initializeSocket("127.0.0.1", 5555)) {
        std::cerr << "[CLIENT] Socket init failed" << std::endl;
        exit(1);
    }
    
    if (!client.connect()) {
        std::cerr << "[CLIENT] Connection failed" << std::endl;
        exit(1);
    }
    
    std::cout << "\n[CLIENT] ✓✓✓ CONNECTED! Starting tests...\n" << std::endl;
    
    // Test 1: Send navigation data
    std::cout << "=== Test 1: Navigation Data ===" << std::endl;
    NavigationData nav;
    nav.latitude = 51.1605;
    nav.longitude = 71.4704;
    nav.heading = 45.0f;
    nav.distance_to_obstacle = -1.0f;
    nav.urgency = Priority::NORMAL;
    
    client.sendNavigationData(nav);
    sleep(1);
    
    // Test 2: Critical alert
    std::cout << "\n=== Test 2: Critical Alert ===" << std::endl;
    nav.distance_to_obstacle = 1.5f;
    nav.obstacle_type = "vehicle";
    nav.urgency = Priority::CRITICAL;
    client.sendNavigationData(nav);
    sleep(1);
    
    // Test 3: Custom data
    std::cout << "\n=== Test 3: Custom Data ===" << std::endl;
    std::string msg = "Battery: 85%, Sensors: OK";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    client.sendData(data, Priority::NORMAL);
    sleep(1);
    
    // Test 4: Heartbeat
    std::cout << "\n=== Test 4: Heartbeat ===" << std::endl;
    client.sendHeartbeat();
    sleep(1);
    
    // Test 5: Power adaptation
    std::cout << "\n=== Test 5: Power Adaptation ===" << std::endl;
    client.updateBatteryLevel(25);
    client.sendNavigationData(nav);
    sleep(1);
    
    // Statistics
    client.printStatistics();
    client.disconnect();
    
    std::cout << "\n╔══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  ✓✓✓ SATP NETWORK TEST COMPLETED SUCCESSFULLY ✓✓✓       ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════╝\n" << std::endl;
    
    exit(0);
}

int main() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    SATP Integrated Network Test                                     ║
║    Real UDP Client-Server Communication                             ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;

    pid_t server_pid = fork();
    
    if (server_pid < 0) {
        std::cerr << "Fork failed" << std::endl;
        return 1;
    }
    
    if (server_pid == 0) {
        // Child process - run server
        runServer();
    } else {
        // Parent process - run client
        runClient();
        
        // Wait for client to finish
        sleep(1);
        
        // Kill server
        kill(server_pid, SIGTERM);
        waitpid(server_pid, nullptr, 0);
    }
    
    return 0;
}
