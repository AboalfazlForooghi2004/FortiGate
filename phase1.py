#!/usr/bin/env python3
"""
Phase 1 - Export FortiGate Addresses and Groups

This script connects to a FortiGate device using the API and:
1. Exports all Address Objects.
2. Exports all Address Groups.
3. Saves the results to result_json/fortigate_data.json.
4. Displays a human-readable summary table.

Requirements:
- .env file with FORTIGATE_IP, FORTIGATE_TOKEN, (optional) FORTIGATE_VDOM
- fortigate_api_helper.py with FortigateAPIHelper class
"""

import os
import json
from dotenv import load_dotenv
from fortigate_api_helper import FortigateAPIHelper, logger

# ---------------------------- Utility Functions ----------------------------

def summarize_address(addr: dict) -> str:
    """
    Generate a human-readable summary of an address object.
    Supports 'ipmask', 'iprange', 'fqdn', 'wildcard', and generic types.
    """
    if addr.get("subnet"):
        return addr["subnet"]
    if addr.get("start-ip") and addr.get("end-ip"):
        return f'{addr["start-ip"]} - {addr["end-ip"]}'
    if addr.get("fqdn"):
        return addr["fqdn"]
    if addr.get("wildcard"):
        return f'wildcard: {addr["wildcard"]}'
    if addr.get("type"):
        return addr["type"]
    return "unknown"


def trim(s: str, width: int = 60) -> str:
    """Trim a string to the specified width, adding ellipsis if too long."""
    s = str(s)
    return s if len(s) <= width else s[: width - 3] + "..."


def print_table(rows: list[list[str]], headers: list[str]):
    """
    Print a formatted table in console.
    - rows: List of row lists
    - headers: Column headers
    """
    if not rows:
        return
    
    # Determine column widths
    col_widths = []
    for i, h in enumerate(headers):
        col_widths.append(max(len(h), *(len(trim(r[i])) for r in rows)))
    
    sep = "  "
    
    # Print header
    header_line = sep.join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))
    
    # Print rows
    for r in rows:
        print(sep.join(trim(c).ljust(w) for c, w in zip(r, col_widths)))
    print()


# ---------------------------- Export Functions ----------------------------

def export_fortigate_data(api: FortigateAPIHelper) -> dict:
    """
    Export all addresses and address groups from FortiGate.
    
    Returns:
        dict: {
            "addresses": [...],
            "groups": [...],
            "summary": {...}
        }
    """
    # Fetch all address objects
    logger.info("Fetching Address Objects...")
    addresses_response = api.get('firewall/address')
    addresses = addresses_response.get('results', [])
    logger.info(f" Found {len(addresses)} Address Objects")
    
    # Fetch all address groups
    logger.info("Fetching Address Groups...")
    groups_response = api.get('firewall/addrgrp')
    groups = groups_response.get('results', [])
    logger.info(f" Found {len(groups)} Address Groups")
    
    # Create summary statistics
    summary = {
        "total_addresses": len(addresses),
        "total_groups": len(groups),
        "address_types": {}
    }
    
    # Count addresses by type
    for addr in addresses:
        addr_type = addr.get('type', 'unknown')
        summary["address_types"][addr_type] = summary["address_types"].get(addr_type, 0) + 1
    
    return {
        "addresses": addresses,
        "groups": groups,
        "summary": summary
    }


def display_export_data(data: dict):
    """
    Display exported data in a readable console format:
    - Summary
    - Address Objects table
    - Address Groups table
    """
    addresses = data.get("addresses", [])
    groups = data.get("groups", [])
    summary = data.get("summary", {})
    
    # ------------------- SUMMARY -------------------
    print("\n" + "="*60)
    print("           FortiGate Export Summary")
    print("="*60)
    print(f"Addresses      : {len(addresses)}")
    print(f"Address Groups : {len(groups)}")
    
    if "address_types" in summary:
        print("\nAddress Types:")
        for addr_type, count in summary["address_types"].items():
            print(f"  {addr_type:15s}: {count}")
    
    print("="*60 + "\n")
    
    # ------------------- ADDRESSES -------------------
    if addresses:
        addr_rows = []
        for a in addresses:
            name = a.get("name", "<no-name>")
            addr_type = a.get("type", "unknown")
            value = summarize_address(a)
            comment = a.get("comment") or a.get("uuid") or ""
            addr_rows.append([name, addr_type, value, comment])
        
        print("Address Objects:")
        print_table(addr_rows, ["NAME", "TYPE", "VALUE", "COMMENT / UUID"])
    else:
        print("No addresses found.\n")
    
    # ------------------- GROUPS -------------------
    if groups:
        grp_rows = []
        for g in groups:
            name = g.get("name", "<no-name>")
            members = g.get("member", [])
            member_names = []
            for m in members:
                if isinstance(m, dict):
                    member_names.append(m.get("name", "<unknown>"))
                else:
                    member_names.append(str(m))
            members_s = ", ".join(member_names)
            grp_rows.append([name, members_s])
        
        print("Address Groups:")
        print_table(grp_rows, ["GROUP NAME", "MEMBERS"])
    else:
        print("No address groups found.\n")


# ---------------------------- Main Execution ------------------------------

def main():
    """Main execution function: load env, connect, export, save, display."""
    load_dotenv()
    fortigate_ip = os.getenv("FORTIGATE_IP")
    token = os.getenv("FORTIGATE_TOKEN")
    vdom = os.getenv("FORTIGATE_VDOM", "root")
    
    base_url = f'http://{fortigate_ip}/api/v2/cmdb/'

    try:
        # Initialize FortiGate API helper
        api = FortigateAPIHelper(base_url=base_url, token=token, vdom=vdom)
        logger.info("Starting FortiGate data export...")
        
        # Export data
        data = export_fortigate_data(api)
        
        # Ensure result_json folder exists
        result_folder = "result_json"
        os.makedirs(result_folder, exist_ok=True)

        # Save to JSON file inside result_json/
        output_file = os.path.join(result_folder, "fortigate_data.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info(f"Data exported to {output_file}")
        
        # Display summary and tables
        display_export_data(data)
        
        print(f"\nFull data saved to: {output_file}")
        print("You can view it in a pretty format using: python pretty_fortigate.py\n")
        
        return 0
    
    except Exception as e:
        logger.exception(" Phase 1 failed with error")
        print(f"\n Error: {e}\n")
        return 1


if __name__ == "__main__":
    exit(main())
