# Makefile for SATP Protocol Prototype
# Research Project: Privacy and Security of IoT for Visually Impaired People

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = satp_demo
NETWORK_SERVER = satp_server
NETWORK_CLIENT = satp_client

SOURCES = satp_demo.cpp
SERVER_SOURCES = satp_server_test.cpp
CLIENT_SOURCES = satp_client_test.cpp

HEADERS = satp_protocol.h satp_encryption.h satp_client.h
NETWORK_HEADERS = satp_network_server.h satp_network_client.h

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: all clean run help install-deps network server client test-network

all: $(TARGET)
	@echo "$(GREEN)✓ SATP Protocol prototype built successfully!$(NC)"
	@echo "$(YELLOW)Run with: make run$(NC)"
	@echo "$(BLUE)For network test: make network$(NC)"

$(TARGET): $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)Building SATP Protocol prototype...$(NC)"
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

# Build network components
network: $(NETWORK_SERVER) $(NETWORK_CLIENT)
	@echo "$(GREEN)✓ Network components built successfully!$(NC)"
	@echo "$(BLUE)Start server: ./$(NETWORK_SERVER)$(NC)"
	@echo "$(BLUE)Start client: ./$(NETWORK_CLIENT)$(NC)"

$(NETWORK_SERVER): $(SERVER_SOURCES) $(HEADERS) $(NETWORK_HEADERS)
	@echo "$(YELLOW)Building SATP Network Server...$(NC)"
	$(CXX) $(CXXFLAGS) $(SERVER_SOURCES) -o $(NETWORK_SERVER) $(LDFLAGS)

$(NETWORK_CLIENT): $(CLIENT_SOURCES) $(HEADERS) $(NETWORK_HEADERS)
	@echo "$(YELLOW)Building SATP Network Client...$(NC)"
	$(CXX) $(CXXFLAGS) $(CLIENT_SOURCES) -o $(NETWORK_CLIENT) $(LDFLAGS)

run: $(TARGET)
	@echo "$(GREEN)Starting SATP Protocol Demonstration...$(NC)"
	@echo ""
	./$(TARGET)

# Convenience targets
server: $(NETWORK_SERVER)
	@echo "$(GREEN)Starting SATP Server on port 5555...$(NC)"
	./$(NETWORK_SERVER)

client: $(NETWORK_CLIENT)
	@echo "$(GREEN)Starting SATP Client...$(NC)"
	./$(NETWORK_CLIENT)

# Run automated network test (requires tmux or manual terminal setup)
test-network: network
	@echo "$(YELLOW)═══════════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)Network Test Instructions:$(NC)"
	@echo "$(YELLOW)═══════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "1. Open a NEW terminal and run:"
	@echo "   $(BLUE)./$(NETWORK_SERVER)$(NC)"
	@echo ""
	@echo "2. Then in this terminal run:"
	@echo "   $(BLUE)./$(NETWORK_CLIENT)$(NC)"
	@echo ""
	@echo "$(YELLOW)═══════════════════════════════════════════════════$(NC)"

clean:
	@echo "$(YELLOW)Cleaning build files...$(NC)"
	rm -f $(TARGET) $(NETWORK_SERVER) $(NETWORK_CLIENT)
	@echo "$(GREEN)✓ Clean complete$(NC)"

# Install OpenSSL dependencies (Ubuntu/Debian)
install-deps:
	@echo "$(YELLOW)Installing OpenSSL development libraries...$(NC)"
	@if command -v apt-get > /dev/null; then \
		sudo apt-get update && sudo apt-get install -y libssl-dev; \
		echo "$(GREEN)✓ Dependencies installed$(NC)"; \
	elif command -v yum > /dev/null; then \
		sudo yum install -y openssl-devel; \
		echo "$(GREEN)✓ Dependencies installed$(NC)"; \
	else \
		echo "$(RED)Please install libssl-dev manually for your system$(NC)"; \
	fi

help:
	@echo "SATP Protocol Prototype - Makefile Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make              - Build the SATP prototype"
	@echo "  make run          - Build and run the demonstration"
	@echo "  make clean        - Remove build files"
	@echo "  make install-deps - Install required dependencies (OpenSSL)"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - C++17 compatible compiler"
	@echo "  - OpenSSL development libraries (libssl-dev)"
	@echo ""
	@echo "Project: Privacy and Security of IoT for Visually Impaired People"
	@echo "Team: Aitkazy B., Bekbulat A., Baktash A.P., Kurmanbekov A., Turtulov R."
	@echo "Course: MIIL 3222 - Research Methods and Tools"
	@echo "Institution: Astana IT University"
