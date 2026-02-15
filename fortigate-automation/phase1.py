#!/usr/bin/env python3
"""
Phase 1 v2.0 - Export FortiGate Addresses and Groups
Enhanced with comprehensive error handling and recovery
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Import enhanced helpers
try:
    from fortigate_api_helper_v2 import FortigateAPIHelper
    from error_handler import (
        ErrorHandler, ValidationError, handle_errors,
        RecoveryManager, Validator
    )
    from logging_config import setup_syslog_logger
except ImportError:
    print("❌ Required modules not found. Please ensure:")
    print("   - fortigate_api_helper_v2.py")
    print("   - error_handler.py")
    print("   - logging_config.py")
    sys.exit(1)

# Setup
logger = setup_syslog_logger("phase1")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

# Result folder
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)


# ==================== Utility Functions ====================
def summarize_address(addr: dict) -> str:
    """Generate human-readable summary of address object"""
    try:
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
    except Exception as e:
        logger.warning(f"Error summarizing address: {e}")
        return "error"


def trim(s: str, width: int = 60) -> str:
    """Trim string to specified width"""
    s = str(s)
    return s if len(s) <= width else s[: width - 3] + "..."


def print_table(rows: List[List[str]], headers: List[str]):
    """Print formatted table"""
    if not rows:
        print("   (No data to display)")
        return
    
    try:
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
    except Exception as e:
        logger.error(f"Table printing error: {e}")
        print("⚠️  Error displaying table")


# ==================== Export Functions ====================
@handle_errors(error_handler, {"phase": "phase1", "operation": "export"})
def export_fortigate_data(api: FortigateAPIHelper) -> Dict:
    """
    Export all addresses and address groups with error handling
    
    Returns:
        Dict with addresses, groups, and summary
        Or error dict if failed
    """
    result = {
        "success": False,
        "addresses": [],
        "groups": [],
        "summary": {},
        "errors": []
    }
    
    # Ensure connection
    try:
        api.ensure_connection()
    except Exception as e:
        result["errors"].append(f"Connection failed: {str(e)}")
        return result
    
    # Fetch addresses with retry
    logger.info("Fetching Address Objects...")
    print("📥 Fetching Address Objects...")
    
    try:
        addresses_response = api.get('firewall/address')
        addresses = addresses_response.get('results', [])
        result["addresses"] = addresses
        logger.info(f"✅ Found {len(addresses)} Address Objects")
        print(f"   ✅ Found {len(addresses)} addresses")
    except Exception as e:
        error_msg = f"Failed to fetch addresses: {str(e)}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
        print(f"   ❌ {error_msg}")
        # Continue with partial data
    
    # Fetch groups with retry
    logger.info("Fetching Address Groups...")
    print("📥 Fetching Address Groups...")
    
    try:
        groups_response = api.get('firewall/addrgrp')
        groups = groups_response.get('results', [])
        result["groups"] = groups
        logger.info(f"✅ Found {len(groups)} Address Groups")
        print(f"   ✅ Found {len(groups)} groups")
    except Exception as e:
        error_msg = f"Failed to fetch groups: {str(e)}"
        logger.error(error_msg)
        result["errors"].append(error_msg)
        print(f"   ❌ {error_msg}")
        # Continue with partial data
    
    # Create summary
    try:
        summary = {
            "total_addresses": len(result["addresses"]),
            "total_groups": len(result["groups"]),
            "address_types": {},
            "export_timestamp": datetime.now().isoformat(),
            "partial_export": len(result["errors"]) > 0
        }
        
        # Count by type
        for addr in result["addresses"]:
            addr_type = addr.get('type', 'unknown')
            summary["address_types"][addr_type] = \
                summary["address_types"].get(addr_type, 0) + 1
        
        result["summary"] = summary
        result["success"] = True
    except Exception as e:
        logger.error(f"Summary generation failed: {e}")
        result["errors"].append(f"Summary generation failed: {str(e)}")
    
    return result


def display_export_data(data: Dict):
    """Display exported data in readable format"""
    if not data.get("success"):
        print("\n❌ Export failed or incomplete")
        if data.get("errors"):
            print("\nErrors:")
            for err in data["errors"]:
                print(f"  • {err}")
        return
    
    addresses = data.get("addresses", [])
    groups = data.get("groups", [])
    summary = data.get("summary", {})
    
    # Summary
    print("\n" + "="*60)
    print("           FortiGate Export Summary")
    print("="*60)
    print(f"Addresses      : {len(addresses)}")
    print(f"Address Groups : {len(groups)}")
    
    if summary.get("partial_export"):
        print("\n⚠️  WARNING: Partial export (some data may be missing)")
    
    if "address_types" in summary:
        print("\nAddress Types:")
        for addr_type, count in summary["address_types"].items():
            print(f"  {addr_type:15s}: {count}")
    
    print("="*60 + "\n")
    
    # Addresses table
    if addresses:
        print("Address Objects:")
        addr_rows = []
        for a in addresses:
            try:
                name = a.get("name", "<no-name>")
                addr_type = a.get("type", "unknown")
                value = summarize_address(a)
                comment = a.get("comment") or a.get("uuid", "")[:20]
                addr_rows.append([name, addr_type, value, comment])
            except Exception as e:
                logger.warning(f"Error processing address: {e}")
                continue
        
        if addr_rows:
            print_table(addr_rows, ["NAME", "TYPE", "VALUE", "COMMENT"])
    else:
        print("No addresses found.\n")
    
    # Groups table
    if groups:
        print("Address Groups:")
        grp_rows = []
        for g in groups:
            try:
                name = g.get("name", "<no-name>")
                members = g.get("member", [])
                member_names = []
                for m in members:
                    if isinstance(m, dict):
                        member_names.append(m.get("name", "<unknown>"))
                    else:
                        member_names.append(str(m))
                members_s = ", ".join(member_names[:5])  # Limit display
                if len(member_names) > 5:
                    members_s += f" ... (+{len(member_names) - 5} more)"
                grp_rows.append([name, members_s])
            except Exception as e:
                logger.warning(f"Error processing group: {e}")
                continue
        
        if grp_rows:
            print_table(grp_rows, ["GROUP NAME", "MEMBERS"])
    else:
        print("No address groups found.\n")


def save_export_data(data: Dict, output_file: Path) -> bool:
    """Save export data to JSON with backup"""
    try:
        # Create backup if file exists
        if output_file.exists():
            backup_file = recovery.backup_state("phase1_export", {
                "previous_file": str(output_file)
            })
            if backup_file:
                logger.info(f"Created backup: {backup_file}")
        
        # Save new data
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Data exported to {output_file}")
        return True
    
    except IOError as e:
        error = ValidationError(f"Failed to save export: {str(e)}")
        error_handler.log_error(error, {"file": str(output_file)})
        print(f"\n❌ Failed to save export: {e}")
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error saving export: {e}")
        print(f"\n❌ Unexpected error: {e}")
        return False


# ==================== Main Execution ====================
def load_config() -> Dict:
    """Load configuration from environment"""
    load_dotenv()
    
    fortigate_ip = os.getenv("FORTIGATE_IP")
    token = os.getenv("FORTIGATE_TOKEN")
    vdom = os.getenv("FORTIGATE_VDOM", "root")
    
    # Validate
    try:
        validator.validate_non_empty(fortigate_ip, "FORTIGATE_IP")
        validator.validate_non_empty(token, "FORTIGATE_TOKEN")
    except ValidationError as e:
        error_handler.log_error(e, {"phase": "phase1", "operation": "config"})
        raise
    
    return {
        "ip": fortigate_ip,
        "token": token,
        "vdom": vdom
    }


def main() -> int:
    """Main execution with comprehensive error handling"""
    print("\n" + "="*60)
    print("   Phase 1: FortiGate Data Export (Enhanced)")
    print("="*60 + "\n")
    
    # Load config
    try:
        config = load_config()
    except ValidationError:
        print("\n❌ Configuration error. Please check .env file.")
        print("   Required: FORTIGATE_IP, FORTIGATE_TOKEN")
        return 1
    except Exception as e:
        print(f"\n❌ Failed to load configuration: {e}")
        return 1
    
    # Initialize API
    base_url = f'http://{config["ip"]}/api/v2/cmdb/'
    
    try:
        api = FortigateAPIHelper(
            base_url=base_url,
            token=config["token"],
            vdom=config["vdom"],
            error_handler=error_handler
        )
        logger.info("API initialized successfully")
    except Exception as e:
        print(f"\n❌ Failed to initialize API: {e}")
        print("   Check FortiGate IP and network connectivity")
        return 1
    
    # Test connection
    print("🔌 Testing connection...")
    if not api.test_connection():
        print("❌ Connection test failed")
        print("   Check:")
        print("   • FortiGate IP is reachable")
        print("   • API token is valid")
        print("   • Network connectivity")
        return 1
    
    print("✅ Connection successful\n")
    
    # Export data
    logger.info("Starting FortiGate data export...")
    data = export_fortigate_data(api)
    
    # Check if export succeeded
    if not data.get("success"):
        print("\n❌ Export failed")
        return 1
    
    # Display results
    display_export_data(data)
    
    # Save to file
    output_file = RESULT_DIR / "fortigate_data.json"
    print(f"💾 Saving to {output_file}...")
    
    if save_export_data(data, output_file):
        print(f"✅ Export completed: {output_file}\n")
        
        # Print error summary if any
        error_summary = api.get_error_summary()
        if error_summary['total_errors'] > 0:
            print(f"⚠️  Note: {error_summary['total_errors']} errors occurred during export")
            print(f"   Check logs for details\n")
        
        return 0
    else:
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Export cancelled by user")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in Phase 1")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        # Cleanup old backups
        try:
            recovery.cleanup_old_backups(keep_last=5)
        except:
            pass
    
    sys.exit(exit_code)