#!/usr/bin/env python3
"""
SATP Protocol Web Demonstration Server
Interactive visualization of Secure Assistive Transport Protocol
"""

import json
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
# PROTOCOL ENUMS (matching C++ implementation)
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
}

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
    if len(protocol_state["events"]) > 50:
        protocol_state["events"] = protocol_state["events"][:50]

    # Emit to all connected clients
    socketio.emit("protocol_event", event)


def get_security_color(level):
    """Get color for security level"""
    colors = {
        "MAXIMUM": "#10b981",  # green
        "BALANCED": "#3b82f6",  # blue
        "MINIMAL": "#f59e0b",  # orange
        "EMERGENCY": "#ef4444",  # red
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
    """Initiate SATP connection"""
    protocol_state["connection_status"] = "initiating"
    add_event("CONNECTION", "Initiating SATP handshake...", False)

    # Simulate handshake sequence
    def handshake_sequence():
        time.sleep(0.5)
        protocol_state["connection_status"] = "handshaking"
        add_event("HANDSHAKE", "Sending HELLO message", False)
        socketio.emit(
            "message_animation",
            {"direction": "client_to_server", "type": "HELLO", "color": "#3b82f6"},
        )

        time.sleep(0.8)
        add_event("HANDSHAKE", "Received HELLO_ACK from server", False)
        socketio.emit(
            "message_animation",
            {"direction": "server_to_client", "type": "HELLO_ACK", "color": "#10b981"},
        )

        time.sleep(0.5)
        add_event("HANDSHAKE", "Exchanging encryption keys", False)
        socketio.emit(
            "message_animation",
            {
                "direction": "client_to_server",
                "type": "KEY_EXCHANGE",
                "color": "#8b5cf6",
            },
        )

        time.sleep(0.8)
        add_event("CONNECTION", "Session established successfully", False)
        protocol_state["connection_status"] = "connected"
        socketio.emit("connection_status", {"status": "connected"})

    threading.Thread(target=handshake_sequence, daemon=True).start()
    return jsonify({"status": "ok"})


@app.route("/api/disconnect", methods=["POST"])
def disconnect():
    """Disconnect SATP session"""
    add_event("CONNECTION", "Closing SATP session", False)
    protocol_state["connection_status"] = "disconnected"
    protocol_state["messages_sent"] = 0
    protocol_state["messages_received"] = 0
    socketio.emit("connection_status", {"status": "disconnected"})
    return jsonify({"status": "ok"})


@app.route("/api/send_data", methods=["POST"])
def send_data():
    """Send navigation data"""
    if protocol_state["connection_status"] != "connected":
        return jsonify({"error": "Not connected"}), 400

    data = request.json
    priority = data.get("priority", "NORMAL")

    protocol_state["messages_sent"] += 1

    # Determine color based on priority
    priority_colors = {
        "LOW": "#6b7280",
        "NORMAL": "#3b82f6",
        "HIGH": "#f59e0b",
        "CRITICAL": "#ef4444",
    }

    add_event(
        "DATA",
        f"Sending navigation data (Priority: {priority})",
        priority == "CRITICAL",
    )
    socketio.emit(
        "message_animation",
        {
            "direction": "client_to_server",
            "type": "DATA",
            "color": priority_colors.get(priority, "#3b82f6"),
            "priority": priority,
        },
    )

    return jsonify({"status": "ok", "messages_sent": protocol_state["messages_sent"]})


@app.route("/api/battery", methods=["POST"])
def update_battery():
    """Update battery level and adapt security"""
    data = request.json
    new_level = int(data.get("level", 100))
    old_level = protocol_state["battery_level"]

    protocol_state["battery_level"] = new_level

    # Check if security level should change
    old_security = protocol_state["security_level"]
    new_security = update_security_level(new_level)

    if old_security != new_security:
        protocol_state["security_level"] = new_security
        add_event(
            "SECURITY",
            f"Security level adapted: {old_security} → {new_security}",
            new_security == "EMERGENCY",
        )
        socketio.emit(
            "security_change",
            {
                "old_level": old_security,
                "new_level": new_security,
                "color": get_security_color(new_security),
            },
        )

    add_event("POWER", f"Battery level: {new_level}%", new_level < 20)
    socketio.emit(
        "battery_update", {"level": new_level, "security_level": new_security}
    )

    return jsonify({"status": "ok", "security_level": new_security})


@app.route("/api/privacy", methods=["POST"])
def update_privacy():
    """Update privacy level"""
    data = request.json
    new_level = data.get("level", "PSEUDONYMOUS")

    old_level = protocol_state["privacy_level"]
    protocol_state["privacy_level"] = new_level

    add_event("PRIVACY", f"Privacy mode changed: {old_level} → {new_level}", False)
    socketio.emit("privacy_update", {"level": new_level})

    return jsonify({"status": "ok"})


@app.route("/api/scenario/<scenario_name>", methods=["POST"])
def run_scenario(scenario_name):
    """Run demonstration scenario"""
    protocol_state["current_scenario"] = scenario_name

    def scenario_runner():
        if scenario_name == "battery_drain":
            run_battery_drain_scenario()
        elif scenario_name == "critical_alert":
            run_critical_alert_scenario()
        elif scenario_name == "privacy_demo":
            run_privacy_scenario()
        elif scenario_name == "normal_nav":
            run_normal_navigation_scenario()

    threading.Thread(target=scenario_runner, daemon=True).start()
    return jsonify({"status": "ok", "scenario": scenario_name})


# ============================================================================
# DEMO SCENARIOS
# ============================================================================


def run_battery_drain_scenario():
    """Scenario 1: Battery drain and security adaptation"""
    add_event("SCENARIO", "🔋 Starting battery drain demonstration", False)

    for battery in range(100, 5, -15):
        time.sleep(1.5)
        protocol_state["battery_level"] = battery

        old_security = protocol_state["security_level"]
        new_security = update_security_level(battery)

        if old_security != new_security:
            protocol_state["security_level"] = new_security
            add_event(
                "SECURITY",
                f"⚡ Auto-adapted: {new_security} (Battery: {battery}%)",
                new_security == "EMERGENCY",
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
            "battery_update", {"level": battery, "security_level": new_security}
        )

        # Send data packet
        protocol_state["messages_sent"] += 1
        socketio.emit(
            "message_animation",
            {
                "direction": "client_to_server",
                "type": "DATA",
                "color": get_security_color(new_security),
            },
        )

    add_event("SCENARIO", "✅ Battery drain scenario completed", False)
    protocol_state["current_scenario"] = None


def run_critical_alert_scenario():
    """Scenario 2: Critical safety alert"""
    add_event("SCENARIO", "🚨 Critical obstacle detected!", True)

    # Send high-priority alert
    for i in range(3):
        time.sleep(0.3)
        protocol_state["messages_sent"] += 1
        socketio.emit(
            "message_animation",
            {
                "direction": "client_to_server",
                "type": "ALERT",
                "color": "#ef4444",
                "priority": "CRITICAL",
            },
        )
        add_event("ALERT", f"⚠️ Emergency navigation alert #{i + 1}", True)

    time.sleep(1)
    add_event("SCENARIO", "✅ Critical alert scenario completed", False)
    protocol_state["current_scenario"] = None


def run_privacy_scenario():
    """Scenario 3: Privacy mode demonstration"""
    add_event("SCENARIO", "🔒 Privacy mode demonstration", False)

    privacy_levels = ["IDENTIFIED", "PSEUDONYMOUS", "ANONYMOUS"]

    for level in privacy_levels:
        time.sleep(1.5)
        protocol_state["privacy_level"] = level
        add_event("PRIVACY", f"Privacy mode: {level}", False)
        socketio.emit("privacy_update", {"level": level})

        # Send data with current privacy setting
        protocol_state["messages_sent"] += 1
        socketio.emit(
            "message_animation",
            {"direction": "client_to_server", "type": "DATA", "color": "#8b5cf6"},
        )

    add_event("SCENARIO", "✅ Privacy demonstration completed", False)
    protocol_state["current_scenario"] = None


def run_normal_navigation_scenario():
    """Scenario 4: Normal navigation data"""
    add_event("SCENARIO", "🧭 Normal navigation demonstration", False)

    locations = [
        {"lat": 51.1605, "lon": 71.4704, "desc": "Starting location"},
        {"lat": 51.1610, "lon": 71.4710, "desc": "Walking north"},
        {"lat": 51.1615, "lon": 71.4715, "desc": "Approaching intersection"},
        {"lat": 51.1620, "lon": 71.4720, "desc": "Destination reached"},
    ]

    for loc in locations:
        time.sleep(1.2)
        add_event(
            "NAVIGATION",
            f"📍 {loc['desc']} ({loc['lat']:.4f}, {loc['lon']:.4f})",
            False,
        )
        protocol_state["messages_sent"] += 1
        socketio.emit(
            "message_animation",
            {"direction": "client_to_server", "type": "DATA", "color": "#3b82f6"},
        )

    add_event("SCENARIO", "✅ Navigation scenario completed", False)
    protocol_state["current_scenario"] = None


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
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("SATP Protocol Web Demonstration Server")
    print("=" * 70)
    print(f"Server starting at http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 70)

    socketio.run(
        app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True
    )
