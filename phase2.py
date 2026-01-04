#!/usr/bin/env python3
# phase2.py - Env + multi-IP + validation + result-json folder

import os
import json
import sys
from collections import defaultdict
import ipaddress
from typing import List, Dict, Any

from dotenv import load_dotenv
from fortigate_api_helper import FortigateAPIHelper, logger

# ----------------------------- Setup result folder -------------------------
RESULT_DIR = "result_json"   # پوشه خروجی استاندارد برای همه فازها
os.makedirs(RESULT_DIR, exist_ok=True)


# ----------------------------- Helpers -------------------------------------

def load_config_from_env() -> Dict[str, str]:
    """Load FortiGate connection info from environment variables."""
    load_dotenv()
    fg_ip = os.getenv("FORTIGATE_IP")
    fg_token = os.getenv("FORTIGATE_TOKEN")
    fg_vdom = os.getenv("FORTIGATE_VDOM", "root")
    fg_protocol = os.getenv("FORTIGATE_PROTOCOL", "http").lower()

    missing = []
    if not fg_ip: missing.append("FORTIGATE_IP")
    if not fg_token: missing.append("FORTIGATE_TOKEN")
    if missing:
        logger.error("Missing environment variables: %s", ", ".join(missing))
        raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

    return {"ip": fg_ip, "token": fg_token, "vdom": fg_vdom, "protocol": fg_protocol}


def normalize_ip_list_input(user_input: str) -> List[str]:
    """Parse comma/space separated IPs or read from file (@filename)."""
    user_input = user_input.strip()
    if not user_input: return []

    if user_input.startswith("@"):
        fname = user_input[1:]
        try:
            with open(fname, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            ips = []
            for l in lines:
                parts = [p.strip() for p in l.replace(",", " ").split()]
                ips.extend([p for p in parts if p])
            return ips
        except Exception as e:
            logger.error("Failed to read IP file '%s': %s", fname, e)
            raise

    return [p.strip() for p in user_input.replace(",", " ").split() if p.strip()]


def validate_ip_addr(addr: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def ip_in_address_object(target_ip: str, addr: Dict[str, Any]) -> bool:
    """Check if target_ip falls inside a given Address Object."""
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        logger.warning("Invalid target IP passed: %s", target_ip)
        return False

    addr_type = addr.get('type', '')

    if addr_type == 'ipmask' and 'subnet' in addr:
        subnet_str = addr['subnet']
        try:
            if ' ' in subnet_str and '/' not in subnet_str:
                ip_part, mask_part = subnet_str.split(maxsplit=1)
                net = ipaddress.ip_network(f"{ip_part}/{mask_part}", strict=False)
            else:
                net = ipaddress.ip_network(subnet_str, strict=False)
            return ip in net
        except Exception as e:
            logger.warning("Failed to parse subnet '%s': %s", subnet_str, e)
            return False

    elif addr_type == 'iprange' and 'start-ip' in addr and 'end-ip' in addr:
        try:
            start = ipaddress.ip_address(addr['start-ip'])
            end = ipaddress.ip_address(addr['end-ip'])
            return start <= ip <= end
        except Exception as e:
            logger.warning("Failed to parse IP range: %s", e)
            return False

    return False


def find_duplicates(addresses: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Detect duplicate address objects by type & value."""
    dup_map: Dict[str, List[str]] = defaultdict(list)
    for addr in addresses:
        t = addr.get('type')
        if t == 'ipmask' and 'subnet' in addr: key = f"ipmask:{addr['subnet']}"
        elif t == 'iprange' and 'start-ip' in addr and 'end-ip' in addr: key = f"iprange:{addr['start-ip']}-{addr['end-ip']}"
        else: continue
        dup_map[key].append(addr.get('name', '<no-name>'))
    return {k: v for k, v in dup_map.items() if len(v) > 1}


def find_groups_with_ip(groups: List[Dict[str, Any]], addresses: List[Dict[str, Any]], target_ip: str) -> List[str]:
    """Return list of groups containing the target IP."""
    addr_lookup = {a['name']: a for a in addresses if 'name' in a}
    matched_groups: List[str] = []
    for group in groups:
        for member in group.get('member', []):
            member_name = member.get('name') if isinstance(member, dict) else str(member)
            addr = addr_lookup.get(member_name)
            if addr and ip_in_address_object(target_ip, addr):
                matched_groups.append(group.get('name', '<no-name>'))
                break
    return matched_groups


def save_json_report(data: Dict[str, Any], filename: str):
    """Save JSON report into the RESULT_DIR folder."""
    path = os.path.join(RESULT_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("Saved Phase 2 output to %s", path)
        print(f"\nPhase 2 output saved to: {path}")
    except Exception as e:
        logger.exception("Failed to save JSON report: %s", e)
        print(f"\n Failed to save results: {e}")


# ----------------------------- Main ----------------------------------------

def main() -> int:
    try:
        cfg = load_config_from_env()
    except Exception as e:
        print(f"Configuration error: {e}")
        return 1

    protocol = cfg["protocol"]
    fortigate_ip = cfg["ip"]
    token = cfg["token"]
    vdom = cfg["vdom"]

    base_url = f"{protocol}://{fortigate_ip}/api/v2/cmdb/"

    try:
        api = FortigateAPIHelper(base_url=base_url, token=token, vdom=vdom)
    except Exception as e:
        logger.exception("Failed to initialize API helper: %s", e)
        print(f"\n Error initializing API helper: {e}\n")
        return 1

    try:
        addr_resp = api.get('firewall/address')
        addresses = addr_resp.get('results', []) if isinstance(addr_resp, dict) else []

        grp_resp = api.get('firewall/addrgrp')
        groups = grp_resp.get('results', []) if isinstance(grp_resp, dict) else []

    except Exception as e:
        logger.exception("Failed to fetch data: %s", e)
        print(f"\n Error fetching data: {e}\n")
        return 1

    duplicates = find_duplicates(addresses)

    raw_input = input("Enter IP(s) to search (comma/space separated) or @filename: ").strip()
    if not raw_input:
        print("No IP provided; exiting.")
        return 0

    try:
        ip_list = normalize_ip_list_input(raw_input)
    except Exception as e:
        print(f" Failed to parse IP input: {e}")
        return 1

    valid_ips, invalid_ips = [], []
    for ip in ip_list:
        (valid_ips if validate_ip_addr(ip) else invalid_ips).append(ip)

    if invalid_ips: print("Invalid IPs skipped:", ", ".join(invalid_ips))
    if not valid_ips:
        print("No valid IPs to search. Exiting.")
        return 1

    results_for_ips = {}
    for ip in valid_ips:
        matched_groups = find_groups_with_ip(groups=groups, addresses=addresses, target_ip=ip)
        results_for_ips[ip] = {"matched_groups": matched_groups, "count": len(matched_groups)}

    print("\n=== Phase 2 Result ===")
    print(f"Total Addresses   : {len(addresses)}")
    print(f"Total Groups      : {len(groups)}")
    print(f"Duplicate Objects : {len(duplicates)}")
    if duplicates:
        print("\nDuplicate Address Objects:")
        for k, v in duplicates.items():
            print(f"  {k} -> {', '.join(v)}")
    print("\nIP Search Results:")
    for ip, res in results_for_ips.items():
        print(f"  {ip} -> {res['count']} group(s)")
        for g in res['matched_groups']:
            print(f"    - {g}")

    # --------------------- Save JSON output ---------------------
    out = {
        "fortigate": {"ip": fortigate_ip, "vdom": vdom},
        "summary": {
            "total_addresses": len(addresses),
            "total_groups": len(groups),
            "duplicate_count": len(duplicates)
        },
        "duplicates": duplicates,
        "ip_search": results_for_ips
    }

    save_json_report(out, "phase2_result.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
