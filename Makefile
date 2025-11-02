# Makefile for SATP Protocol Prototype
# Research Project: Privacy and Security of IoT for Visually Impaired People

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = satp_demo
SOURCES = satp_demo.cpp
HEADERS = satp_protocol.h satp_encryption.h satp_client.h

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
NC = \033[0m # No Color

.PHONY: all clean run help install-deps

all: $(TARGET)
	@echo "$(GREEN)✓ SATP Protocol prototype built successfully!$(NC)"
	@echo "$(YELLOW)Run with: make run$(NC)"

$(TARGET): $(SOURCES) $(HEADERS)
	@echo "$(YELLOW)Building SATP Protocol prototype...$(NC)"
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	@echo "$(GREEN)Starting SATP Protocol Demonstration...$(NC)"
	@echo ""
	./$(TARGET)

clean:
	@echo "$(YELLOW)Cleaning build files...$(NC)"
	rm -f $(TARGET)
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
