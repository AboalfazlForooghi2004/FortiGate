#!/usr/bin/env python3
"""
Phase 4 Lab - FortiGate Automation (Env + Interactive Policy Fields)

Features:
- Uses .env for FortiGate IP, API token, VDOM if available
- VIPs: HTTP, HTTPS, SSH (interactive internal IPs)
- VIP Group: created empty if not exists, members added automatically
- Firewall Policy: all fields collected interactively
- Output saved to JSON in result_json folder
"""

import os
import json
import requests
from typing import List
from pathlib import Path

# ================================
# Load .env values (if available)
# ================================
from dotenv import load_dotenv
load_dotenv()  # looks for .env in current directory

FORTIGATE_IP = os.getenv("FORTIGATE_IP")
FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN")
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
FORTIGATE_PROTOCOL = os.getenv("FORTIGATE_PROTOCOL", "http").lower()
FORTIGATE_TIMEOUT = int(os.getenv("FORTIGATE_TIMEOUT", "10"))

# ================================
# Helper Functions
# ================================
def ask(prompt: str, default: str = None) -> str:
    """Prompt for user input with optional default value"""
    if default:
        full = f"{prompt} [{default}]: "
    else:
        full = f"{prompt}: "
    val = input(full).strip()
    return val if val else default

def split_names(s: str) -> List[str]:
    """Split comma-separated names into trimmed list"""
    return [x.strip() for x in s.split(",") if x.strip()] if s else []

# ================================
# FortiGate Connection Info
# ================================
FGT_IP = FORTIGATE_IP or ask("FortiGate IP", "192.168.55.238")
API_TOKEN = FORTIGATE_TOKEN or ask("API Token (Bearer)")
VDOM = FORTIGATE_VDOM
PROTOCOL = FORTIGATE_PROTOCOL
TIMEOUT = FORTIGATE_TIMEOUT

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

BASE_URL = f"{PROTOCOL}://{FGT_IP}"

# ================================
# Output folder for JSON results
# ================================
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = RESULT_DIR / "phase4_lab.json"

# ================================
# Network / VIP Info
# ================================
WAN_IF = ask("WAN Interface (extintf)", "port2")
LAN_IF = ask("LAN Interface (dstintf)", "port4")
EXT_IP = ask("External IP on WAN (extip)", "10.8.10.1")

vip_http_ip  = ask("Internal IP for HTTP (VIP_HTTP)", "192.168.1.10")
vip_https_ip = ask("Internal IP for HTTPS (VIP_HTTPS)", "192.168.1.11")
vip_ssh_ip   = ask("Internal IP for SSH (VIP_SSH)", "192.168.1.12")

VIP_LIST = [
    {"name": "VIP_HTTP",  "ip": vip_http_ip,  "port": 80},
    {"name": "VIP_HTTPS", "ip": vip_https_ip, "port": 443},
    {"name": "VIP_SSH",   "ip": vip_ssh_ip,   "port": 22},
]

VIP_GROUP_NAME = ask("VIP Group Name", "VIP_PUBLISH_GROUP")
POLICY_DEFAULT_NAME = "AUTO_PUBLISH_POLICY"

# ================================
# FortiGate REST Helpers
# ================================
def object_exists(endpoint: str, name: str) -> bool:
    """Check if FortiGate object exists"""
    try:
        r = requests.get(f"{BASE_URL}/api/v2/cmdb/firewall/{endpoint}/{name}",
                         headers=HEADERS, verify=False, timeout=TIMEOUT)
        return r.status_code == 200
    except requests.RequestException as e:
        print(f"[ERROR] request failed when checking {endpoint}/{name}: {e}")
        return False

def create_vip(vip: dict):
    """Create a VIP on FortiGate"""
    if object_exists("vip", vip["name"]):
        return {"status": "exists"}

    payload = {
        "name": vip["name"],
        "type": "ipv4",
        "extintf": WAN_IF,
        "extip": EXT_IP,
        "mappedip": [{"range": vip["ip"]}],
        "portforward": "disable"
    }

    try:
        r = requests.post(f"{BASE_URL}/api/v2/cmdb/firewall/vip",
                          headers=HEADERS, json=payload, verify=False, timeout=TIMEOUT)
        data = r.json() if r.text else r.text
    except requests.RequestException as e:
        return {"status": "failed", "http_status": 0, "data": str(e)}

    return {"status": "created" if r.status_code in (200,201) else "failed",
            "http_status": r.status_code, "data": data}

def create_vip_group_empty(group_name: str, interface: str, comment: str = "") -> dict:
    """Create VIP Group if not exists (empty)"""
    if object_exists("vipgrp", group_name):
        return {"status": "exists"}

    payload = {
        "name": group_name,
        "interface": interface,
        "member": [],
        "comment": comment
    }

    try:
        r = requests.post(f"{BASE_URL}/api/v2/cmdb/firewall/vipgrp",
                          headers=HEADERS, json=payload, verify=False, timeout=TIMEOUT)
        data = r.json() if r.text else r.text
    except requests.RequestException as e:
        return {"status": "failed_create", "http_status": 0, "data": str(e), "payload": payload}

    return {"status": "created_empty" if r.status_code in (200,201) else "failed_create",
            "http_status": r.status_code, "data": data}

def vipgrp_put_members(name: str, interface: str, members: List[str], comment: str = "") -> dict:
    """Update VIP Group members"""
    payload = {
        "interface": interface,
        "member": [{"name": m} for m in members],
        "comment": comment
    }

    try:
        r = requests.put(f"{BASE_URL}/api/v2/cmdb/firewall/vipgrp/{name}",
                         headers=HEADERS, json=payload, verify=False, timeout=TIMEOUT)
        data = r.json() if r.text else r.text
    except requests.RequestException as e:
        return {"status": "failed_update", "http_status": 0, "data": str(e), "members": members}

    return {"status": "updated_members" if r.status_code in (200,201) else "failed_update",
            "http_status": r.status_code, "data": data, "members": members}

# ================================
# Policy creation (interactive all fields)
# ================================
def create_policy_interactive(vip_group_name: str):
    """Create firewall policy interactively with user input"""
    print("\n-- Enter Policy fields (leave empty to use default) --")

    policy_name = ask("Policy name", POLICY_DEFAULT_NAME)
    srcintf_list = [{"name": n} for n in split_names(ask("Source interfaces (comma-separated)", WAN_IF))]
    dstintf_list = [{"name": n} for n in split_names(ask("Destination interfaces (comma-separated)", LAN_IF))]
    srcaddr_list = [{"name": n} for n in split_names(ask("Source addresses (comma-separated, e.g. all)", "all"))]
    dstaddr_list = [{"name": n} for n in split_names(ask("Destination addresses (comma-separated, VIP group)", vip_group_name))]
    action = ask("Action (accept/deny)", "accept")
    schedule = ask("Schedule (name or always)", "always")
    service_list = [{"name": n} for n in split_names(ask("Service(s) comma-separated, e.g. ALL or HTTP,HTTPS", "ALL"))]
    logtraffic = ask("Logtraffic (all/utm/disable)", "all")
    nat = ask("NAT (enable/disable)", "disable")

    payload = {
        "name": policy_name,
        "srcintf": srcintf_list,
        "dstintf": dstintf_list,
        "srcaddr": srcaddr_list,
        "dstaddr": dstaddr_list,
        "action": action,
        "schedule": schedule,
        "service": service_list,
        "logtraffic": logtraffic,
        "nat": nat
    }

    if object_exists("policy", policy_name):
        return {"status": "exists", "policy": policy_name}

    try:
        r = requests.post(f"{BASE_URL}/api/v2/cmdb/firewall/policy",
                          headers=HEADERS, json=payload, verify=False, timeout=TIMEOUT)
        data = r.json() if r.text else r.text
    except requests.RequestException as e:
        return {"status": "failed_create", "http_status": 0, "data": str(e), "payload": payload}

    return {"status": "created" if r.status_code in (200,201) else "failed",
            "http_status": r.status_code, "data": data, "payload": payload}

# ================================
# MAIN
# ================================
def main():
    report = {"vip": [], "vipgrp": {}, "policy": {}}
    print("=== Phase 4 Lab Started ===")

    # 1) VIPs
    vip_names = []
    for vip in VIP_LIST:
        res = create_vip(vip)
        report["vip"].append({vip["name"]: res})
        if res.get("status") in ("created", "exists"):
            vip_names.append(vip["name"])

    # 2) VIP Group
    grp_res = create_vip_group_empty(VIP_GROUP_NAME, WAN_IF, "Auto-generated by script")
    report["vipgrp"]["create"] = grp_res

    if vip_names:
        put_res = vipgrp_put_members(VIP_GROUP_NAME, WAN_IF, vip_names, "Auto-generated by script")
        report["vipgrp"]["put_members"] = put_res
    else:
        report["vipgrp"]["put_members"] = {"status": "no_vips_to_add"}

    # 3) Policy
    policy_res = create_policy_interactive(VIP_GROUP_NAME)
    report["policy"] = policy_res

    # 4) Save output
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("=== DONE ===")
    print(f" Phase 4 Lab completed! Output saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
