#!/usr/bin/env python3
"""
FINAL PHASE – WAN FAILOVER MONITOR (Enhanced)

Improvements:
- Better error handling for "both WANs down" scenario
- Graceful shutdown
- State persistence across restarts
- Debouncing to prevent flapping
- Health check before activation
"""

import os
import time
import json
import signal
import sys
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from fortigate_api_helper import FortigateAPIHelper
from logging_config import setup_syslog_logger

# ================= LOGGING =================
logger = setup_syslog_logger("final_phase")

# ================= ENV =====================
load_dotenv()

FGT_IP = os.getenv("FORTIGATE_IP")
TOKEN = os.getenv("FORTIGATE_TOKEN")
VDOM = os.getenv("FORTIGATE_VDOM", "root")
PROTO = os.getenv("FORTIGATE_PROTOCOL", "http")
TIMEOUT = int(os.getenv("FORTIGATE_TIMEOUT", 10))

if not FGT_IP or not TOKEN:
    logger.error("FORTIGATE_IP or FORTIGATE_TOKEN not set in .env")
    print("❌ Error: FORTIGATE_IP or FORTIGATE_TOKEN not set in .env")
    sys.exit(1)

BASE_URL = f"{PROTO}://{FGT_IP}/api/v2/cmdb"

# ================= API HELPER ==============
try:
    api = FortigateAPIHelper(
        base_url=BASE_URL,
        token=TOKEN,
        vdom=VDOM,
        timeout=TIMEOUT,
        verify_ssl=False
    )
    
    # Test connection
    if not api.test_connection():
        logger.error("Failed to connect to FortiGate")
        print(" Cannot connect to FortiGate. Check IP, token, and network.")
        sys.exit(1)
        
except Exception as e:
    logger.error(f"Failed to initialize API: {e}")
    print(f" API initialization failed: {e}")
    sys.exit(1)

# ================= CONFIG ==================
WAN1 = os.getenv("WAN1_INTERFACE", "port1")
WAN2 = os.getenv("WAN2_INTERFACE", "port2")

VIP1 = os.getenv("VIP1_NAME", "VIP_FAILOVER_WAN1")
VIP2 = os.getenv("VIP2_NAME", "VIP_FAILOVER_WAN2")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
DEBOUNCE_COUNT = int(os.getenv("DEBOUNCE_COUNT", "3"))  # Require 3 consecutive changes
MODE = os.getenv("MODE", "LIVE")

# ================= JSON OUTPUT ==================
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
STATE_FILE = RESULT_DIR / "phase_state.json"
HISTORY_FILE = RESULT_DIR / "phase_history.json"

# ================= STATE MANAGEMENT ==================
class StateManager:
    def __init__(self):
        self.state = self._load_state()
        self.history = self._load_history()
        
    def _load_state(self):
        try:
            if STATE_FILE.exists():
                with STATE_FILE.open("r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load state: {e}")
        
        return {
            "check": 0,
            "last_active_vip": None,
            "failover_count": 0,
            "wan1_down_count": 0,
            "wan2_down_count": 0,
            "both_down_count": 0
        }
    
    def _load_history(self):
        try:
            if HISTORY_FILE.exists():
                with HISTORY_FILE.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("events", [])
        except Exception as e:
            logger.warning(f"Could not load history: {e}")
        return []
    
    def save_state(self, check, wan1_up, wan2_up, active_vip, failovers):
        self.state.update({
            "check": check,
            "timestamp": datetime.now().isoformat(),
            "WAN1": {"interface": WAN1, "status": "UP" if wan1_up else "DOWN"},
            "WAN2": {"interface": WAN2, "status": "UP" if wan2_up else "DOWN"},
            "active_vip": active_vip,
            "failover_count": failovers,
            "mode": MODE
        })
        
        try:
            with STATE_FILE.open("w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def add_history_event(self, event_type, details):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "details": details
        }
        self.history.append(event)
        
        # Keep last 100 events
        if len(self.history) > 100:
            self.history = self.history[-100:]
        
        try:
            with HISTORY_FILE.open("w", encoding="utf-8") as f:
                json.dump({"events": self.history}, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save history: {e}")

state_manager = StateManager()

# ================= INTERFACE STATUS =================
def interface_up(name: str) -> bool:
    """Check if interface is UP with retry"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            data = api.get(f"system/interface/{name}")
            if data and "results" in data and data["results"]:
                status = data["results"][0].get("status", "down")
                return status == "up"
        except Exception as e:
            logger.error(f"Error checking {name} status (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(1)
    
    # If all retries fail, assume down
    return False

# ================= VIP HEALTH CHECK =================
def vip_exists(vip_name: str) -> bool:
    """Check if VIP exists"""
    try:
        response = api.get(f"firewall/vip/{vip_name}")
        return response.get("status") != "error"
    except:
        return False

def validate_vips():
    """Validate that both VIPs exist before starting"""
    missing = []
    if not vip_exists(VIP1):
        missing.append(VIP1)
    if not vip_exists(VIP2):
        missing.append(VIP2)
    
    if missing:
        logger.error(f"VIPs not found: {', '.join(missing)}")
        print(f"\n Error: VIPs not found: {', '.join(missing)}")
        print("Please create these VIPs before running failover monitor.")
        return False
    return True

# ================= POLICY MANAGEMENT =================
def policies_using_vip(vip: str) -> list:
    """Return list of policy IDs that use the given VIP"""
    try:
        policies = api.get("firewall/policy")["results"]
        used = []
        for p in policies:
            dst = [d.get("name", "") for d in p.get("dstaddr", [])]
            if vip in dst:
                used.append(p["policyid"])
        return used
    except Exception as e:
        logger.error(f"Error getting policies for VIP {vip}: {e}")
        return []

def set_policy(pid: int, enable: bool) -> bool:
    """Enable or disable a specific firewall policy"""
    try:
        api.put(f"firewall/policy/{pid}", {
            "status": "enable" if enable else "disable"
        })
        return True
    except Exception as e:
        logger.error(f"Failed to {'enable' if enable else 'disable'} policy {pid}: {e}")
        return False

def activate(vip_on, vip_off) -> bool:
    """Activate vip_on and deactivate vip_off"""
    success = True
    
    # Enable policies for active VIP
    for pid in policies_using_vip(vip_on):
        if not set_policy(pid, True):
            success = False
            logger.error(f"Failed to enable policy {pid} for {vip_on}")
    
    # Disable policies for inactive VIP
    for pid in policies_using_vip(vip_off):
        if not set_policy(pid, False):
            success = False
            logger.error(f"Failed to disable policy {pid} for {vip_off}")
    
    return success

# ================= OUTPUT BOX ===================
def icon(up):
    return "🟢 UP  " if up else "🔴 DOWN"

def print_box(check, w1, w2, active_vip, failovers, both_down_count):
    """Nicely formatted console output"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if active_vip == VIP1:
        active_path = "WAN1 (Primary)"
    elif active_vip == VIP2:
        active_path = "WAN2 (Backup)"
    else:
        active_path = "⚠️  NONE (BOTH DOWN)"

    print("\n" + "="*62)
    print("║      FortiGate WAN Failover Live Monitor              ║")
    print("="*62)
    print(f"║ Check #:        {check:<38}║")
    print(f"║ Time:           {now:<38}║")
    print("="*62)
    print(f"║ {WAN1:8s}:      {icon(w1):<38}║")
    print(f"║ {WAN2:8s}:      {icon(w2):<38}║")
    print("="*62)
    print(f"║ Active Path:    ➜ {active_path:<34}║")
    print(f"║ Active VIP:     🔵 {active_vip or 'NONE':<34}║")
    print("="*62)
    print(f"║ Failovers:      ⚠️  {failovers:<34}║")
    
    if both_down_count > 0:
        print(f"║ Both Down:      🚨 {both_down_count} checks{'':<26}║")
    
    print(f"║ Mode:           {MODE:<38}║")
    print("="*62)
    print("Press Ctrl+C to stop monitoring")

# ================= SHUTDOWN HANDLER =====================
shutdown_flag = False

def signal_handler(sig, frame):
    global shutdown_flag
    print("\n\n🛑 Shutdown signal received...")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ================= MAIN LOOP =====================
def main():
    global shutdown_flag
    
    print(f"""
==========================================
  FINAL PHASE – WAN FAILOVER MONITOR
==========================================
FortiGate : {FGT_IP}
VDOM      : {VDOM}
WAN1      : {WAN1} -> {VIP1}
WAN2      : {WAN2} -> {VIP2}
Interval  : {POLL_INTERVAL}s
Mode      : {MODE}
==========================================
""")

    # Validate VIPs exist
    if not validate_vips():
        return 1

    failovers = state_manager.state.get("failover_count", 0)
    last_active = state_manager.state.get("last_active_vip")
    check = state_manager.state.get("check", 0)
    both_down_count = 0
    
    # Debouncing state
    pending_change = None
    pending_count = 0

    try:
        while not shutdown_flag:
            check += 1

            # -------------------- INTERFACE CHECK --------------------
            w1 = interface_up(WAN1)
            w2 = interface_up(WAN2)

            # -------------------- DECIDE ACTIVE VIP --------------------
            if w1:
                desired_vip = VIP1
            elif w2:
                desired_vip = VIP2
            else:
                desired_vip = None
                both_down_count += 1
                logger.critical("BOTH WANS DOWN!")

            # -------------------- DEBOUNCING --------------------
            if desired_vip != last_active:
                if pending_change == desired_vip:
                    pending_count += 1
                else:
                    pending_change = desired_vip
                    pending_count = 1
                
                # Execute change only after DEBOUNCE_COUNT consecutive checks
                if pending_count >= DEBOUNCE_COUNT:
                    # -------------------- FAILOVER / FAILBACK --------------------
                    if last_active is not None:
                        failovers += 1

                    if desired_vip == VIP1:
                        success = activate(VIP1, VIP2)
                        msg = "FAILBACK → WAN1 ACTIVE"
                        logger.warning(msg)
                        state_manager.add_history_event("FAILBACK", {
                            "from": VIP2, "to": VIP1, "success": success
                        })
                        
                    elif desired_vip == VIP2:
                        success = activate(VIP2, VIP1)
                        msg = "FAILOVER → WAN2 ACTIVE"
                        logger.warning(msg)
                        state_manager.add_history_event("FAILOVER", {
                            "from": VIP1, "to": VIP2, "success": success
                        })
                        
                    else:
                        msg = "BOTH WANS DOWN – NO ACTIVE VIP"
                        logger.error(msg)
                        state_manager.add_history_event("BOTH_DOWN", {
                            "count": both_down_count
                        })

                    last_active = desired_vip
                    pending_change = None
                    pending_count = 0
                    
            else:
                # State is stable
                pending_change = None
                pending_count = 0
                both_down_count = 0  # Reset count when at least one WAN is up

            # -------------------- SAVE STATE --------------------
            state_manager.save_state(check, w1, w2, last_active, failovers)

            # -------------------- CONSOLE OUTPUT --------------------
            print_box(check, w1, w2, last_active, failovers, both_down_count)

            time.sleep(POLL_INTERVAL)

    except Exception as e:
        logger.exception(f"Fatal error in main loop: {e}")
        print(f"\n❌ Fatal error: {e}")
        return 1
    
    finally:
        logger.info("Monitoring stopped gracefully")
        print("\n✅ Monitoring stopped gracefully")
        print(f"Total failovers: {failovers}")
        print(f"State saved to: {STATE_FILE}")
    
    return 0

# ================= RUN =====================
if __name__ == "__main__":
    sys.exit(main())