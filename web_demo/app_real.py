#!/usr/bin/env python3
"""
SATP Protocol Web Demonstration Server - REAL C++ INTEGRATION
Interactive visualization with actual SATP C++ client and server
"""

import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from enum import Enum
from queue import Empty, Queue

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

# ============================================================================
# PROTOCOL ENUMS
# ============================================================================


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


# ============================================================================
# GLOBAL STATE
# ============================================================================

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
}

# Process handles
server_process = None
client_process = None
output_threads = []

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


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
    """Get color for security level"""
    colors = {
        "MAXIMUM": "#10b981",
        "BALANCED": "#3b82f6",
        "MINIMAL": "#f59e0b",
        "EMERGENCY": "#ef4444",
    }
    return colors.get(level, "#6b7280")


def update_security_level(battery):
    """Update security level based on battery"""
    if battery > 70:
        return "MAXIMUM"
    elif battery > 30:
        return "BALANCED"
    elif battery > 10:
        return "MINIMAL"
    else:
        return "EMERGENCY"


# ============================================================================
# C++ PROCESS MANAGEMENT
# ============================================================================


def read_process_output(process, process_name):
    """Read and process output from C++ program"""
    while True:
        try:
            line = process.stdout.readline()
            if not line:
                break

            line = line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # Parse and categorize output
            parse_cpp_output(line, process_name)

        except Exception as e:
            print(f"Error reading {process_name} output: {e}")
            break


def parse_cpp_output(line, source):
    """Parse C++ program output and generate events"""
    global protocol_state

    # Skip decorative lines
    if "═" in line or "║" in line or "╔" in line or "╚" in line:
        return

    # Detect event types from C++ output
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

    elif "[SATP-NET]" in line or "[SATP]" in line or "[TEST]" in line:
        if "connecting" in line.lower():
            add_event("CONNECTION", "Client initiating connection...", False)
            protocol_state["connection_status"] = "initiating"
            protocol_state["client_running"] = True
            socketio.emit("connection_status", {"status": "initiating"})

        elif "connected" in line.lower() and "✓" in line:
            add_event("CONNECTION", "Client connected successfully", False)
            protocol_state["connection_status"] = "connected"
            socketio.emit("connection_status", {"status": "connected"})

        elif "sending hello" in line.lower():
            add_event("HANDSHAKE", "Sending HELLO message", False)
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "HELLO", "color": "#3b82f6"},
            )

        elif "received hello_ack" in line.lower():
            add_event("HANDSHAKE", "Received HELLO_ACK from server", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "server_to_client",
                    "type": "HELLO_ACK",
                    "color": "#10b981",
                },
            )

        elif "key exchange" in line.lower():
            add_event("HANDSHAKE", "Exchanging encryption keys", False)
            socketio.emit(
                "message_animation",
                {
                    "direction": "client_to_server",
                    "type": "KEY_EXCHANGE",
                    "color": "#8b5cf6",
                },
            )

        elif "sending" in line.lower() and (
            "location" in line.lower() or "navigation" in line.lower()
        ):
            protocol_state["messages_sent"] += 1
            add_event("DATA", "Sending navigation data", False)

            # Extract GPS coordinates if present
            lat_match = re.search(r"lat:?\s*([\d.]+)", line, re.IGNORECASE)
            lon_match = re.search(r"lon:?\s*([\d.]+)", line, re.IGNORECASE)
            if lat_match and lon_match:
                add_event(
                    "NAVIGATION",
                    f"📍 Position: ({lat_match.group(1)}, {lon_match.group(1)})",
                    False,
                )

        elif "obstacle" in line.lower() and "critical" in line.lower():
            add_event("ALERT", "⚠️ CRITICAL: Obstacle detected!", True)
            socketio.emit(
                "message_animation",
                {
                    "direction": "client_to_server",
                    "type": "ALERT",
                    "color": "#ef4444",
                    "priority": "CRITICAL",
                },
            )

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

        elif "security level" in line.lower():
            for level in ["MAXIMUM", "BALANCED", "MINIMAL", "EMERGENCY"]:
                if level in line.upper():
                    protocol_state["security_level"] = level
                    add_event("SECURITY", f"Security level: {level}", False)
                    socketio.emit(
                        "security_change",
                        {"new_level": level, "color": get_security_color(level)},
                    )
                    break

        elif "sent successfully" in line.lower() or "✓ sent" in line.lower():
            socketio.emit(
                "message_animation",
                {"direction": "client_to_server", "type": "DATA", "color": "#3b82f6"},
            )

        elif "disconnected" in line.lower() or "disconnecting" in line.lower():
            add_event("CONNECTION", "Client disconnected", False)
            protocol_state["connection_status"] = "disconnected"
            protocol_state["client_running"] = False
            socketio.emit("connection_status", {"status": "disconnected"})

    # Print to console for debugging
    print(f"[{source}] {line}")


def start_server():
    """Start the C++ SATP server"""
    global server_process

    try:
        add_event("SYSTEM", f"Starting SATP server on port {SERVER_PORT}...", False)

        server_process = subprocess.Popen(
            [SERVER_BINARY, str(SERVER_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )

        # Start thread to read output
        thread = threading.Thread(
            target=read_process_output, args=(server_process, "SERVER"), daemon=True
        )
        thread.start()
        output_threads.append(thread)

        time.sleep(1)  # Give server time to start
        return True

    except Exception as e:
        add_event("ERROR", f"Failed to start server: {str(e)}", True)
        return False


def start_client():
    """Start the C++ SATP client"""
    global client_process

    try:
        add_event(
            "SYSTEM",
            f"Starting SATP client (connecting to {SERVER_IP}:{SERVER_PORT})...",
            False,
        )

        client_process = subprocess.Popen(
            [CLIENT_BINARY, SERVER_IP, str(SERVER_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
        )

        # Start thread to read output
        thread = threading.Thread(
            target=read_process_output, args=(client_process, "CLIENT"), daemon=True
        )
        thread.start()
        output_threads.append(thread)

        return True

    except Exception as e:
        add_event("ERROR", f"Failed to start client: {str(e)}", True)
        return False


def stop_server():
    """Stop the C++ SATP server"""
    global server_process

    if server_process:
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
        except:
            server_process.kill()

        server_process = None
        protocol_state["server_running"] = False
        add_event("SYSTEM", "Server stopped", False)


def stop_client():
    """Stop the C++ SATP client"""
    global client_process

    if client_process:
        try:
            client_process.terminate()
            client_process.wait(timeout=5)
        except:
            client_process.kill()

        client_process = None
        protocol_state["client_running"] = False
        add_event("SYSTEM", "Client stopped", False)


# ============================================================================
# WEB ROUTES
# ============================================================================


@app.route("/")
def index():
    """Main dashboard"""
    return render_template("index.html")


@app.route("/api/status")
def get_status():
    """Get current protocol status"""
    return jsonify(protocol_state)


@app.route("/api/connect", methods=["POST"])
def connect():
    """Start server and client"""

    # Start server first
    if not protocol_state["server_running"]:
        if not start_server():
            return jsonify({"error": "Failed to start server"}), 500

    time.sleep(2)  # Wait for server to be ready

    # Start client
    if not protocol_state["client_running"]:
        if not start_client():
            return jsonify({"error": "Failed to start client"}), 500

    return jsonify({"status": "ok"})


@app.route("/api/disconnect", methods=["POST"])
def disconnect():
    """Stop client and server"""
    stop_client()
    time.sleep(1)
    stop_server()

    protocol_state["connection_status"] = "disconnected"
    protocol_state["messages_sent"] = 0
    protocol_state["messages_received"] = 0

    socketio.emit("connection_status", {"status": "disconnected"})
    return jsonify({"status": "ok"})


@app.route("/api/send_data", methods=["POST"])
def send_data():
    """Send data (client runs automatically during test)"""
    if protocol_state["connection_status"] != "connected":
        return jsonify({"error": "Not connected"}), 400

    # The client test program already sends data automatically
    # We just increment the counter
    protocol_state["messages_sent"] += 1

    return jsonify({"status": "ok", "messages_sent": protocol_state["messages_sent"]})


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================


@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    emit("initial_state", protocol_state)
    add_event("SYSTEM", "🌐 Web client connected", False)


@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection"""
    add_event("SYSTEM", "🌐 Web client disconnected", False)


# ============================================================================
# CLEANUP
# ============================================================================


def cleanup():
    """Cleanup on exit"""
    stop_client()
    stop_server()


import atexit

atexit.register(cleanup)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SATP Protocol Web Demonstration Server - REAL C++ INTEGRATION")
    print("=" * 70)
    print(f"Server binary: {SERVER_BINARY}")
    print(f"Client binary: {CLIENT_BINARY}")
    print(f"SATP Port: {SERVER_PORT}")
    print(f"Web server starting at http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 70)

    # Check if binaries exist
    if not os.path.exists(SERVER_BINARY):
        print(f"ERROR: Server binary not found: {SERVER_BINARY}")
        exit(1)

    if not os.path.exists(CLIENT_BINARY):
        print(f"ERROR: Client binary not found: {CLIENT_BINARY}")
        exit(1)

    socketio.run(
        app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True
    )
