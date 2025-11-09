#include "satp_network_server.h"
#include <iostream>
#include <signal.h>

using namespace SATP;

// Global server instance for signal handler
SATPNetworkServer* g_server = nullptr;

void signalHandler(int signum) {
    std::cout << "\n\n[SIGNAL] Interrupt signal received (" << signum << ")" << std::endl;
    if (g_server) {
        g_server->printStatistics();
        g_server->stop();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    SATP Network Server - Real UDP Implementation                    ║
║    Secure Assistive Transport Protocol                              ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;

    // Parse port from command line
    uint16_t port = 5555;  // Default port
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }
    
    std::cout << "[INFO] Server will listen on UDP port: " << port << std::endl;
    std::cout << "[INFO] Press Ctrl+C to stop the server\n" << std::endl;
    
    // Create and start server
    SATPNetworkServer server(port);
    g_server = &server;
    
    // Register signal handler for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    if (!server.start()) {
        std::cerr << "[ERROR] Failed to start server" << std::endl;
        return 1;
    }
    
    // Run server
    server.run();
    
    // Print final statistics
    server.printStatistics();
    server.stop();
    
    return 0;
}
