#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    std::cout << "=== Simple UDP Test ===" << std::endl;
    
    // Server setup
    int server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5556);  // Different port
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Server bind failed" << std::endl;
        return 1;
    }
    std::cout << "Server listening on port 5556" << std::endl;
    
    // Client setup
    int client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(5556);
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);
    
    // Send message
    const char* message = "Hello UDP!";
    ssize_t sent = sendto(client_sock, message, strlen(message), 0,
                          (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    std::cout << "Client sent " << sent << " bytes" << std::endl;
    
    // Receive message
    char buffer[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(server_sock, buffer, sizeof(buffer), 0,
                               (struct sockaddr*)&from_addr, &from_len);
    
    if (received > 0) {
        buffer[received] = '\0';
        std::cout << "Server received " << received << " bytes: " << buffer << std::endl;
        std::cout << "✓ UDP communication works!" << std::endl;
    } else {
        std::cerr << "✗ Failed to receive" << std::endl;
    }
    
    close(server_sock);
    close(client_sock);
    
    return 0;
}
