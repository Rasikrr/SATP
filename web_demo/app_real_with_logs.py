#!/usr/bin/env python3
"""
SATP Protocol Web Demonstration Server - REAL C++ INTEGRATION WITH FILE LOGGING
"""

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from enum import Enum

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "satp-demo-secret-2025"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# ============================================================================
# CONFIGURATION
# ============================================================================

SATP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVER_BINARY = os.path.join(SATP_DIR, "satp_server")
CLIENT_BINARY = os.path.join(SATP_DIR, "satp_client")
SERVER_PORT = 5555
SERVER_IP = "127.0.0.1"

# Logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

SERVER_LOG_FILE = os.path.join(
    LOG_DIR, f"server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
CLIENT_LOG_FILE = os.path.join(
    LOG_DIR, f"client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
COMBINED_LOG_FILE = os.path.join(
    LOG_DIR, f"combined_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

print(f"📁 Логи будут сохранены в:")
print(f"   Server:   {SERVER_LOG_FILE}")
print(f"   Client:   {CLIENT_LOG_FILE}")
print(f"   Combined: {COMBINED_LOG_FILE}")

# ============================================================================
# IMPORT REST OF CODE FROM app_real.py
# ============================================================================

# (Копируем все остальное из app_real.py, но модифицируем функцию read_process_output)


class SecurityLevel(Enum):
    MAXIMUM = 0
    BALANCED = 1
    MINIMAL = 2
    EMERGENCY = 3


class PrivacyLevel(Enum):
    ANONYMOUS = 0
    PSEUDONYMOUS = 1
    IDENTIFIED = 2


class Priority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


protocol_state = {
    "connection_status": "disconnected",
    "battery_level": 100,
    "security_level": "BALANCED",
    "privacy_level": "PSEUDONYMOUS",
    "messages_sent": 0,
    "messages_received": 0,
    "current_scenario": None,
    "events": [],
    "server_running": False,
    "client_running": False,
    "interception_mode": False,
    "intercepted_packets": [],
}

server_process = None
client_process = None
output_threads = []

# Log file handles
server_log = None
client_log = None
combined_log = None


def add_event(event_type, description, is_critical=False):
    """Add event to protocol log"""
    event = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "type": event_type,
        "description": description,
        "is_critical": is_critical,
    }
    protocol_state["events"].insert(0, event)
    if len(protocol_state["events"]) > 100:
        protocol_state["events"] = protocol_state["events"][:100]

    socketio.emit("protocol_event", event)


def get_security_color(level):
    colors = {
        "MAXIMUM": "#10b981",
        "BALANCED": "#3b82f6",
        "MINIMAL": "#f59e0b",
        "EMERGENCY": "#ef4444",
    }
    return colors.get(level, "#6b7280")


def update_security_level(battery):
    if battery > 70:
        return "MAXIMUM"
    elif battery > 30:
        return "BALANCED"
    elif battery > 10:
        return "MINIMAL"
    else:
        return "EMERGENCY"


def simulate_encrypted_packet(plaintext):
    """Simulate what an intercepted encrypted packet looks like"""
    import base64
    import random

    # Generate random bytes to simulate encrypted data
    # Length roughly matches plaintext but with encryption overhead
    encrypted_length = len(plaintext.encode()) + 16  # +16 for IV/tag
    random_bytes = bytes([random.randint(0, 255) for _ in range(encrypted_length)])

    # Convert to hex representation for display
    hex_representation = random_bytes.hex()

    return hex_representation


def read_process_output(process, process_name, log_file):
    """Read and process output from C++ program - WITH FILE LOGGING"""
    while True:
        try:
            line = process.stdout.readline()
            if not line:
                break

            line = line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # Log to file
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log_entry = f"[{timestamp}] [{process_name}] {line}\n"

            if log_file and not log_file.closed:
                log_file.write(log_entry)
                log_file.flush()

            if combined_log and not combined_log.closed:
                combined_log.write(log_entry)
                combined_log.flush()

            # Parse and emit to web interface
            parse_cpp_output(line, process_name)

        except Exception as e:
            if not ("closed file" in str(e) or "I/O operation" in str(e)):
                print(f"Error reading {process_name} output: {e}")
            break


def parse_cpp_output(line, source):
    """Parse C++ program output and generate events - SAME AS app_real.py"""
    global protocol_state

    if "═" in line or "║" in line or "╔" in line or "╚" in line:
        return

    if "[SATP-SERVER]" in line or "[SERVER]" in line:
        if "started successfully" in line.lower():
            add_event("SERVER", "🖥️ Server started successfully", False)
            protocol_state["server_running"] = True
            socketio.emit("server_status", {"running": True})

        elif "listening on port" in line.lower():
            match = re.search(r"port:?\s*(\d+)", line, re.IGNORECASE)
            if match:
                port = match.group(1)
                add_event("SERVER", f"Listening on UDP port {port}", False)

        elif "client connected" in line.lower() or "new session" in line.lower():
            add_event("CONNECTION", "📱 Client connected", False)
            protocol_state["connection_status"] = "connected"
            socketio.emit("connection_status", {"status": "connected"})

        elif "received" in line.lower() and "hello" in line.lower():
            add_event("HANDSHAKE", "Received HELLO from client", False)
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "HELLO", "color": "#3b82f6"},
            )

        elif "sending" in line.lower() and "hello_ack" in line.lower():
            add_event("HANDSHAKE", "Sending HELLO_ACK to client", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "server_to_client",
                    "type": "HELLO_ACK",
                    "color": "#10b981",
                },
            )

        elif "received data" in line.lower() or "navigation data" in line.lower():
            protocol_state["messages_received"] += 1
            add_event("DATA", f"Received data from client", False)
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "DATA", "color": "#3b82f6"},
            )

        elif "decrypted data:" in line.lower():
            # Extract the actual data payload
            match = re.search(r"decrypted data:\s*(.+)", line, re.IGNORECASE)
            if match:
                data_payload = match.group(1).strip()
                add_event("DATA", f"📦 Received: {data_payload}", False)
                socketio.emit("data_received", {"payload": data_payload})

                # If interception mode is on, simulate encrypted packet capture
                if protocol_state["interception_mode"]:
                    encrypted_packet = simulate_encrypted_packet(data_payload)
                    intercepted_data = {
                        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "encrypted": encrypted_packet,
                        "decrypted": data_payload,
                        "security_level": protocol_state["security_level"],
                    }
                    protocol_state["intercepted_packets"].insert(0, intercepted_data)
                    if len(protocol_state["intercepted_packets"]) > 20:
                        protocol_state["intercepted_packets"] = protocol_state[
                            "intercepted_packets"
                        ][:20]

                    socketio.emit("packet_intercepted", intercepted_data)
                    add_event("SECURITY", "⚠️ Packet intercepted by attacker!", True)

        elif "✓ data from" in line.lower():
            # Parse priority and payload size
            priority_match = re.search(r"priority:\s*(\d+)", line, re.IGNORECASE)
            payload_match = re.search(r"payload:\s*(\d+)\s*bytes", line, re.IGNORECASE)

            priority_num = int(priority_match.group(1)) if priority_match else 1
            payload_size = int(payload_match.group(1)) if payload_match else 0

            priority_names = {0: "LOW", 1: "NORMAL", 2: "HIGH", 3: "CRITICAL"}
            priority_name = priority_names.get(priority_num, "NORMAL")

            protocol_state["messages_received"] += 1
            add_event(
                "DATA",
                f"📥 Data packet received (Priority: {priority_name}, {payload_size} bytes)",
                priority_num == 3,
            )

            priority_colors = {
                "LOW": "#6b7280",
                "NORMAL": "#3b82f6",
                "HIGH": "#f59e0b",
                "CRITICAL": "#ef4444",
            }

            socketio.emit(
                "message_animation",
                {
                    "direction": "client_to_server",
                    "type": "DATA",
                    "color": priority_colors.get(priority_name, "#3b82f6"),
                    "priority": priority_name,
                },
            )
            socketio.emit(
                "stats_update",
                {"messages_received": protocol_state["messages_received"]},
            )

    elif (
        "[SATP-NET]" in line
        or "[SATP]" in line
        or "[TEST]" in line
        or "[CLIENT]" in line
    ):
        if "connecting" in line.lower() or "initializing" in line.lower():
            add_event("CONNECTION", "Client initiating connection...", False)
            protocol_state["connection_status"] = "initiating"
            protocol_state["client_running"] = True
            socketio.emit("connection_status", {"status": "initiating"})

        elif "↑ sent hello" in line.lower():
            add_event("HANDSHAKE", "Sending HELLO to server", False)
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "HELLO", "color": "#3b82f6"},
            )

        elif "↓ received hello_ack" in line.lower():
            add_event("HANDSHAKE", "Received HELLO_ACK from server", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "server_to_client",
                    "type": "HELLO_ACK",
                    "color": "#10b981",
                },
            )

        elif "↑ sent key_exchange" in line.lower():
            add_event("HANDSHAKE", "Exchanging encryption keys", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "client_to_server",
                    "type": "KEY_EXCHANGE",
                    "color": "#8b5cf6",
                },
            )

        elif "↓ received session_ready" in line.lower():
            add_event("HANDSHAKE", "Received SESSION_READY from server", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "server_to_client",
                    "type": "SESSION_READY",
                    "color": "#10b981",
                },
            )

        elif "connection established" in line.lower() or "✓✓✓" in line:
            add_event("CONNECTION", "✅ Connection established successfully", False)
            protocol_state["connection_status"] = "connected"
            socketio.emit("connection_status", {"status": "connected"})

        elif "↑ sent data" in line.lower():
            protocol_state["messages_sent"] += 1
            add_event("DATA", f"📤 Sending data packet", False)
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "DATA", "color": "#3b82f6"},
            )
            socketio.emit(
                "stats_update", {"messages_sent": protocol_state["messages_sent"]}
            )

        elif "connected" in line.lower() and "✓" in line:
            add_event("CONNECTION", "Client connected successfully", False)
            protocol_state["connection_status"] = "connected"
            socketio.emit("connection_status", {"status": "connected"})

        elif "battery" in line.lower():
            match = re.search(r"battery:?\s*(\d+)", line, re.IGNORECASE)
            if match:
                level = int(match.group(1))
                protocol_state["battery_level"] = level

                old_security = protocol_state["security_level"]
                new_security = update_security_level(level)

                if old_security != new_security:
                    protocol_state["security_level"] = new_security
                    add_event(
                        "SECURITY",
                        f"Security adapted: {new_security} (Battery: {level}%)",
                        level < 20,
                    )
                    socketio.emit(
                        "security_change",
                        {
                            "old_level": old_security,
                            "new_level": new_security,
                            "color": get_security_color(new_security),
                        },
                    )

                socketio.emit(
                    "battery_update", {"level": level, "security_level": new_security}
                )

    print(f"[{source}] {line}")


def start_server():
    global server_process, server_log

    try:
        add_event("SYSTEM", f"Starting SATP server on port {SERVER_PORT}...", False)

        # Create new log file with unique timestamp
        log_file_path = os.path.join(
            LOG_DIR, f"server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        server_log = open(log_file_path, "w", buffering=1)

        server_process = subprocess.Popen(
            [SERVER_BINARY, str(SERVER_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )

        thread = threading.Thread(
            target=read_process_output,
            args=(server_process, "SERVER", server_log),
            daemon=True,
        )
        thread.start()
        output_threads.append(thread)

        time.sleep(1)
        return True

    except Exception as e:
        add_event("ERROR", f"Failed to start server: {str(e)}", True)
        return False


def start_client():
    global client_process, client_log

    try:
        add_event(
            "SYSTEM",
            f"Starting SATP client (connecting to {SERVER_IP}:{SERVER_PORT})...",
            False,
        )

        # Create new log file with unique timestamp
        log_file_path = os.path.join(
            LOG_DIR, f"client_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        client_log = open(log_file_path, "w", buffering=1)

        client_process = subprocess.Popen(
            [CLIENT_BINARY, SERVER_IP, str(SERVER_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )

        thread = threading.Thread(
            target=read_process_output,
            args=(client_process, "CLIENT", client_log),
            daemon=True,
        )
        thread.start()
        output_threads.append(thread)

        return True

    except Exception as e:
        add_event("ERROR", f"Failed to start client: {str(e)}", True)
        return False


def stop_server():
    global server_process, server_log

    if server_process:
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
        except:
            server_process.kill()

        server_process = None
        protocol_state["server_running"] = False
        add_event("SYSTEM", "Server stopped", False)

    if server_log and not server_log.closed:
        try:
            server_log.close()
        except:
            pass
        server_log = None


def stop_client():
    global client_process, client_log

    if client_process:
        try:
            client_process.terminate()
            client_process.wait(timeout=5)
        except:
            client_process.kill()

        client_process = None
        protocol_state["client_running"] = False
        add_event("SYSTEM", "Client stopped", False)

    if client_log and not client_log.closed:
        try:
            client_log.close()
        except:
            pass
        client_log = None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def get_status():
    return jsonify(protocol_state)


@app.route("/api/connect", methods=["POST"])
def connect():
    global combined_log

    # Create new combined log file with unique timestamp
    if combined_log and not combined_log.closed:
        combined_log.close()

    log_file_path = os.path.join(
        LOG_DIR, f"combined_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    combined_log = open(log_file_path, "w", buffering=1)

    # Reset battery and security levels for new connection
    protocol_state["battery_level"] = 100
    protocol_state["security_level"] = "MAXIMUM"
    socketio.emit("battery_update", {"level": 100, "security_level": "MAXIMUM"})

    if not protocol_state["server_running"]:
        if not start_server():
            return jsonify({"error": "Failed to start server"}), 500

    time.sleep(2)

    if not protocol_state["client_running"]:
        if not start_client():
            return jsonify({"error": "Failed to start client"}), 500

    return jsonify({"status": "ok"})


@app.route("/api/disconnect", methods=["POST"])
def disconnect():
    global combined_log

    stop_client()
    time.sleep(1)
    stop_server()

    if combined_log and not combined_log.closed:
        try:
            combined_log.close()
        except:
            pass

    protocol_state["connection_status"] = "disconnected"
    protocol_state["messages_sent"] = 0
    protocol_state["messages_received"] = 0

    socketio.emit("connection_status", {"status": "disconnected"})
    return jsonify({"status": "ok"})


@app.route("/api/send_data", methods=["POST"])
def send_data():
    if protocol_state["connection_status"] != "connected":
        return jsonify({"error": "Not connected"}), 400

    protocol_state["messages_sent"] += 1
    return jsonify({"status": "ok", "messages_sent": protocol_state["messages_sent"]})


@app.route("/api/interception/toggle", methods=["POST"])
def toggle_interception():
    """Toggle interception mode on/off"""
    protocol_state["interception_mode"] = not protocol_state["interception_mode"]

    if protocol_state["interception_mode"]:
        add_event(
            "SECURITY",
            "🚨 Interception mode activated - Attacker monitoring traffic!",
            True,
        )
    else:
        add_event("SECURITY", "✅ Interception mode deactivated", False)

    socketio.emit(
        "interception_status", {"active": protocol_state["interception_mode"]}
    )
    return jsonify(
        {"status": "ok", "interception_mode": protocol_state["interception_mode"]}
    )


@app.route("/api/interception/packets", methods=["GET"])
def get_intercepted_packets():
    """Get list of intercepted packets"""
    return jsonify({"packets": protocol_state["intercepted_packets"]})


@socketio.on("connect")
def handle_connect():
    emit("initial_state", protocol_state)
    add_event("SYSTEM", "🌐 Web client connected", False)


@socketio.on("disconnect")
def handle_disconnect():
    add_event("SYSTEM", "🌐 Web client disconnected", False)


def cleanup():
    stop_client()
    stop_server()
    if combined_log:
        combined_log.close()


import atexit

atexit.register(cleanup)

if __name__ == "__main__":
    print("=" * 70)
    print("SATP Protocol Web Demonstration Server - REAL C++ INTEGRATION")
    print("WITH FILE LOGGING")
    print("=" * 70)
    print(f"Server binary: {SERVER_BINARY}")
    print(f"Client binary: {CLIENT_BINARY}")
    print(f"SATP Port: {SERVER_PORT}")
    print(f"Web server starting at http://localhost:5000")
    print("=" * 70)
    print(f"📁 Logs directory: {LOG_DIR}")
    print("=" * 70)

    if not os.path.exists(SERVER_BINARY):
        print(f"ERROR: Server binary not found: {SERVER_BINARY}")
        exit(1)

    if not os.path.exists(CLIENT_BINARY):
        print(f"ERROR: Client binary not found: {CLIENT_BINARY}")
        exit(1)

    socketio.run(
        app, host="0.0.0.0", port=5008, debug=False, allow_unsafe_werkzeug=True
    )
