#!/usr/bin/env python3
"""
FINAL PHASE – WAN FAILOVER MONITOR with JSON logging

- Monitors WAN1/WAN2 status.
- Activates VIP1 when WAN1 is UP.
- Activates VIP2 when WAN1 is DOWN and WAN2 is UP.
- Tracks failovers.
- Saves JSON state in result_json/phase_state.json.
- Syslog logging included via FortigateAPIHelper.
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from fortigate_api_helper import FortigateAPIHelper
from logging_config import setup_syslog_logger

# ================= LOGGING =================
logger = setup_syslog_logger("final_phase")

# ================= ENV =====================
load_dotenv()  # load .env variables

FGT_IP = os.getenv("FORTIGATE_IP")
TOKEN = os.getenv("FORTIGATE_TOKEN")
VDOM = os.getenv("FORTIGATE_VDOM", "root")
PROTO = os.getenv("FORTIGATE_PROTOCOL", "http")
TIMEOUT = int(os.getenv("FORTIGATE_TIMEOUT", 10))

BASE_URL = f"{PROTO}://{FGT_IP}/api/v2/cmdb"

# ================= API HELPER ==============
api = FortigateAPIHelper(
    base_url=BASE_URL,
    token=TOKEN,
    vdom=VDOM,
    timeout=TIMEOUT,
    verify_ssl=False
)

# ================= CONFIG ==================
WAN1 = "port1"
WAN2 = "port2"

VIP1 = "VIP_FAILOVER_WAN1"
VIP2 = "VIP_FAILOVER_WAN2"

POLL_INTERVAL = 5
MODE = "LIVE"

# ================= JSON OUTPUT ==================
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
STATE_FILE = RESULT_DIR / "phase_state.json"

def save_json_state(check, wan1_up, wan2_up, active_vip, failovers):
    """Save current monitoring state as JSON for external processing"""
    state = {
        "check": check,
        "timestamp": datetime.now().isoformat(),
        "WAN1": {"interface": WAN1, "status": "UP" if wan1_up else "DOWN"},
        "WAN2": {"interface": WAN2, "status": "UP" if wan2_up else "DOWN"},
        "active_vip": active_vip,
        "failovers": failovers,
        "mode": MODE
    }
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)

# ================= INTERFACE STATUS =================
def interface_up(name: str) -> bool:
    """
    Check if interface is UP.
    Returns True if status=="up", False otherwise.
    """
    data = api.get(f"system/interface/{name}")
    return data["results"][0]["status"] == "up"

# ================= POLICY MANAGEMENT =================
def policies_using_vip(vip: str):
    """
    Return list of policy IDs that use the given VIP.
    """
    policies = api.get("firewall/policy")["results"]
    used = []
    for p in policies:
        dst = [d["name"] for d in p.get("dstaddr", [])]
        if vip in dst:
            used.append(p["policyid"])
    return used

def set_policy(pid: int, enable: bool):
    """
    Enable or disable a specific firewall policy by ID.
    """
    api.put(f"firewall/policy/{pid}", {
        "status": "enable" if enable else "disable"
    })

def activate(vip_on, vip_off):
    """
    Activate vip_on by enabling its policies.
    Deactivate vip_off by disabling its policies.
    """
    for pid in policies_using_vip(vip_on):
        set_policy(pid, True)
    for pid in policies_using_vip(vip_off):
        set_policy(pid, False)

# ================= OUTPUT BOX ===================
def icon(up):
    return "🟢 UP" if up else "🔴 DOWN"

def print_box(check, w1, w2, active_vip, failovers):
    """
    Nicely formatted box-style console output.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    active_path = VIP1 if active_vip == VIP1 else VIP2 if active_vip == VIP2 else "NONE"

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        FortiGate WAN Failover Live Monitor               ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ Check #:        {check:<36}║")
    print(f"║ Time:           {now:<36}║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ WAN1 ({WAN1}):   {icon(w1):<36}║")
    print(f"║ WAN2 ({WAN2}):   {icon(w2):<36}║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ Active Path:    ➜ {active_path:<32}║")
    print(f"║ Active VIP:     🔵 {active_vip or 'NONE':<28}║")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║ Failovers:      ⚠️ {failovers:<33}║")
    print(f"║ Mode:           {MODE:<36}║")
    print("╚══════════════════════════════════════════════════════════╝")
    print("Press Ctrl+C to stop monitoring")

# ================= MAIN LOOP =====================
def main():
    print(f"""
==========================================
  FINAL PHASE – WAN FAILOVER MONITOR
==========================================
FortiGate : {FGT_IP}
VDOM      : {VDOM}
==========================================
""")

    failovers = 0
    last_active = None
    check = 0

    while True:
        check += 1

        # -------------------- INTERFACE CHECK --------------------
        w1 = interface_up(WAN1)  # Check WAN1 status
        w2 = interface_up(WAN2)  # Check WAN2 status

        # -------------------- DECIDE ACTIVE VIP --------------------
        if w1:
            active = VIP1
        elif w2:
            active = VIP2
        else:
            active = None

        # -------------------- FAILOVER / FAILBACK --------------------
        if active != last_active:
            if last_active is not None:
                failovers += 1

            if active == VIP1:
                activate(VIP1, VIP2)  # Activate VIP1, deactivate VIP2
                logger.warning("FAILBACK → WAN1 ACTIVE")
            elif active == VIP2:
                activate(VIP2, VIP1)  # Activate VIP2, deactivate VIP1
                logger.warning("FAILOVER → WAN2 ACTIVE")
            else:
                logger.error("BOTH WANS DOWN – NO ACTIVE VIP")

            last_active = active

        # -------------------- SAVE JSON STATE --------------------
        save_json_state(check, w1, w2, active, failovers)

        # -------------------- CONSOLE OUTPUT --------------------
        print_box(check, w1, w2, active, failovers)

        time.sleep(POLL_INTERVAL)

# ================= RUN =====================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Monitoring stopped")
        print("\n🛑 Monitoring stopped gracefully")
