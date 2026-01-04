#!/usr/bin/env python3
"""
Phase 3 - VIP Creation & Firewall Policy Update (Enhanced)
Features:
- Human-friendly console output
- Syslog logging for technical details
- Result JSON saved to 'result_json/phase3_result.json'
- Fully compatible with FortiGate API v2
"""

import os
import json
import ipaddress
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from fortigate_api_helper import FortigateAPIHelper
from logging_config import setup_syslog_logger

# ------------------------- Setup Logger -------------------------
logger = setup_syslog_logger("phase3")

# ------------------------- Load Environment -------------------------
load_dotenv()
FORTIGATE_IP = os.getenv("FORTIGATE_IP")
FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN")
VDOM = os.getenv("FORTIGATE_VDOM", "root")

if not FORTIGATE_IP or not FORTIGATE_TOKEN:
    print(" Environment variables FORTIGATE_IP or FORTIGATE_TOKEN are missing")
    exit(1)

BASE_URL = f"http://{FORTIGATE_IP}/api/v2/cmdb"
RESULT_FOLDER = Path("result_json")
RESULT_FOLDER.mkdir(exist_ok=True)
RESULT_FILE = RESULT_FOLDER / "phase3_result.json"

# ------------------------- Helpers -------------------------

def human_error(title, reason=None, hint=None):
    """Print user-friendly error message"""
    print(f"\n {title}")
    if reason:
        print(f"   Reason: {reason}")
    if hint:
        print(f"   Hint: {hint}")

def validate_ip(ip_str):
    """Validate IPv4/IPv6 address"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

# ------------------------- VIP Creation -------------------------

def create_vip(api, vip_name, ext_ip, mapped_ip, extintf="any"):
    """Create VIP on FortiGate"""
    vip_data = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [{"range": f"{mapped_ip}-{mapped_ip}"}],
        "arp-reply": "enable"
    }

    try:
        resp = api.post("firewall/vip", vip_data)
        if isinstance(resp, dict) and resp.get("status") == "success":
            print(f" VIP '{vip_name}' created successfully")
            logger.info("VIP created: name=%s extip=%s mappedip=%s vdom=%s", vip_name, ext_ip, mapped_ip, api.vdom)
            return resp

        human_error("VIP creation failed", "FortiGate did not return success", "Check VIP name or IPs")
        logger.error("VIP creation non-success: name=%s response=%s", vip_name, resp)
        return resp

    except Exception as e:
        human_error("Unexpected error during VIP creation", str(e))
        logger.exception("Exception during VIP creation: %s", e)
        return {"status": "error", "error": str(e)}

# ------------------------- Policy Update -------------------------

def update_policy(api, policy_id, vip_name):
    """Attach VIP to firewall policy destination addresses (compatible with FG API)"""
    try:
        #  Get existing policy
        policy_resp = api.get(f"firewall/policy/{policy_id}")
        if not policy_resp or "results" not in policy_resp or not policy_resp["results"]:
            human_error("Policy not found", f"Policy ID {policy_id} does not exist")
            return {"status": "error", "error": "Policy not found"}

        policy = policy_resp["results"][0]

        #  Prepare dstaddr list
        dstaddr = policy.get("dstaddr", [])
        if not isinstance(dstaddr, list):
            dstaddr = []

        # Check if VIP already exists
        if any(addr.get("name") == vip_name for addr in dstaddr):
            print(f" VIP '{vip_name}' already in policy {policy_id}")
            return {"status": "success", "message": "VIP already attached"}

        dstaddr.append({"name": vip_name, "q_origin_key": ""})

        update_data = {
            "dstaddr": dstaddr,
            "nat": policy.get("nat", "disable")  # Preserve existing NAT setting
        }

        print("Debug: PUT payload =", update_data)  #  For troubleshooting
        resp = api.put(f"firewall/policy/{policy_id}", update_data)

        if isinstance(resp, dict) and resp.get("status") == "success":
            print(f" Policy {policy_id} updated with VIP '{vip_name}'")
            logger.info("Policy updated: policy_id=%s vip=%s", policy_id, vip_name)
            return resp

        human_error("Policy update failed", f"FortiGate did not return success: {resp}")
        logger.error("Policy update non-success: policy_id=%s response=%s", policy_id, resp)
        return resp

    except Exception as e:
        human_error("Unexpected error during policy update", str(e))
        logger.exception("Exception during policy update: %s", e)
        return {"status": "error", "error": str(e)}

# ------------------------- Human-friendly Summary -------------------------

def print_summary(vip_name, ext_ip, mapped_ip, policy_id, vip_resp, policy_resp):
    """Print a human-friendly table of the operation"""
    WAN_UP = "🟢 UP" if vip_resp.get("status") == "success" else "🔴 FAILED"
    POLICY_UP = "🟢 UP" if policy_resp.get("status") == "success" else "🔴 FAILED"

    print("\n╔═════════════════════════════════════════╗")
    print("║       Phase 3 VIP & Policy Summary      ║")
    print("╠═════════════════════════════════════════╣")
    print(f"║ VIP Name:      {vip_name:<25}║")
    print(f"║ External IP:   {ext_ip:<25}║")
    print(f"║ Internal IP:   {mapped_ip:<25}║")
    print(f"║ Policy ID:     {policy_id:<25}║")
    print("╠═════════════════════════════════════════╣")
    print(f"║ VIP Status:    {WAN_UP:<25}║")
    print(f"║ Policy Status: {POLICY_UP:<25}║")
    print("╚═════════════════════════════════════════╝")

# ------------------------- Main -------------------------

def main():
    api = FortigateAPIHelper(BASE_URL, FORTIGATE_TOKEN, vdom=VDOM)

    print("\n=== Phase 3: Create VIP & Update Firewall Policy ===\n")

    vip_name = input("VIP name: ").strip()
    if not vip_name:
        print(" VIP name cannot be empty")
        return 1

    ext_ip = input("External IP (extip): ").strip()
    if not validate_ip(ext_ip):
        print(" Invalid External IP")
        return 1

    mapped_ip = input("Mapped/Internal IP: ").strip()
    if not validate_ip(mapped_ip):
        print(" Invalid Internal IP")
        return 1

    extintf = input("External interface [any]: ").strip() or "any"

    try:
        policy_id = int(input("Firewall Policy ID: ").strip())
    except ValueError:
        print(" Policy ID must be a number")
        return 1

    #  Create VIP
    vip_resp = create_vip(api, vip_name, ext_ip, mapped_ip, extintf)

    #  Update Policy
    policy_resp = update_policy(api, policy_id, vip_name)

    #  Save results
    output = {
        "vip_creation": vip_resp,
        "policy_update": policy_resp,
        "timestamp": datetime.now().isoformat()
    }
    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, ensure_ascii=False)
        logger.info("Phase 3 results written to %s", RESULT_FILE)
    except Exception as e:
        logger.error("Failed to write result JSON: %s", e)
        print(" Failed to write result JSON")

    # 4️⃣ Print summary
    print_summary(vip_name, ext_ip, mapped_ip, policy_id, vip_resp, policy_resp)

    return 0

if __name__ == "__main__":
    exit(main())
