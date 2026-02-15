#!/usr/bin/env python3
"""
Phase 2 v2.0 - IP Search with Duplicate Detection
Enhanced with comprehensive error handling and validation
"""

import os
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import ipaddress
from dotenv import load_dotenv

# Import enhanced modules
try:
    from fortigate_api_helper_v2 import FortigateAPIHelper
    from error_handler import (
        ErrorHandler, ValidationError, APIError,
        handle_errors, Validator, RecoveryManager
    )
    from logging_config import setup_syslog_logger
except ImportError:
    print("❌ Required modules not found")
    sys.exit(1)

# Setup
logger = setup_syslog_logger("phase2")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
RESULT_FILE = RESULT_DIR / "phase2_result.json"


# ==================== IP Validation ====================
def validate_ip_list(ip_list: List[str]) -> Tuple[List[str], List[str]]:
    """Validate list of IPs, return (valid, invalid)"""
    valid = []
    invalid = []
    
    for ip in ip_list:
        try:
            validator.validate_ip(ip)
            valid.append(ip)
        except ValidationError:
            invalid.append(ip)
            logger.warning(f"Invalid IP: {ip}")
    
    return valid, invalid


def normalize_ip_list_input(user_input: str) -> Tuple[List[str], Optional[str]]:
    """
    Parse comma/space separated IPs or read from file
    Returns (ip_list, error_message)
    """
    user_input = user_input.strip()
    if not user_input:
        return [], "No input provided"
    
    # File input
    if user_input.startswith("@"):
        filename = user_input[1:]
        try:
            with open(filename, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            
            ips = []
            for line in lines:
                parts = [p.strip() for p in line.replace(",", " ").split()]
                ips.extend([p for p in parts if p])
            
            logger.info(f"Loaded {len(ips)} IPs from file: {filename}")
            return ips, None
        
        except FileNotFoundError:
            error = ValidationError(f"File not found: {filename}")
            error_handler.log_error(error, {"operation": "file_read"})
            return [], f"File not found: {filename}"
        
        except Exception as e:
            logger.error(f"Error reading file {filename}: {e}")
            return [], f"Error reading file: {str(e)}"
    
    # Direct input
    ips = [p.strip() for p in user_input.replace(",", " ").split() if p.strip()]
    return ips, None


# ==================== IP Matching ====================
def ip_in_address_object(target_ip: str, addr: Dict) -> bool:
    """Check if target IP falls inside address object"""
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        logger.warning(f"Invalid target IP: {target_ip}")
        return False
    
    addr_type = addr.get('type', '')
    
    try:
        # ipmask type
        if addr_type == 'ipmask' and 'subnet' in addr:
            subnet_str = addr['subnet']
            
            # Handle space-separated format: "192.168.1.0 255.255.255.0"
            if ' ' in subnet_str and '/' not in subnet_str:
                ip_part, mask_part = subnet_str.split(maxsplit=1)
                net = ipaddress.ip_network(f"{ip_part}/{mask_part}", strict=False)
            else:
                net = ipaddress.ip_network(subnet_str, strict=False)
            
            return ip in net
        
        # iprange type
        elif addr_type == 'iprange' and 'start-ip' in addr and 'end-ip' in addr:
            start = ipaddress.ip_address(addr['start-ip'])
            end = ipaddress.ip_address(addr['end-ip'])
            return start <= ip <= end
        
        return False
    
    except Exception as e:
        logger.warning(f"Error checking IP {target_ip} in {addr.get('name')}: {e}")
        return False


# ==================== Duplicate Detection ====================
def find_duplicates(addresses: List[Dict]) -> Dict[str, List[str]]:
    """Detect duplicate address objects by type & value"""
    dup_map = defaultdict(list)
    
    for addr in addresses:
        try:
            addr_type = addr.get('type')
            name = addr.get('name', '<no-name>')
            
            if addr_type == 'ipmask' and 'subnet' in addr:
                key = f"ipmask:{addr['subnet']}"
                dup_map[key].append(name)
            
            elif addr_type == 'iprange' and 'start-ip' in addr and 'end-ip' in addr:
                key = f"iprange:{addr['start-ip']}-{addr['end-ip']}"
                dup_map[key].append(name)
            
            elif addr_type == 'fqdn' and 'fqdn' in addr:
                key = f"fqdn:{addr['fqdn']}"
                dup_map[key].append(name)
        
        except Exception as e:
            logger.warning(f"Error processing address for duplicates: {e}")
            continue
    
    # Return only duplicates (where count > 1)
    return {k: v for k, v in dup_map.items() if len(v) > 1}


# ==================== Group Search ====================
@handle_errors(error_handler, {"operation": "group_search"})
def find_groups_with_ip(groups: List[Dict], addresses: List[Dict], 
                        target_ip: str) -> List[str]:
    """Find groups containing the target IP"""
    # Build address lookup
    addr_lookup = {a['name']: a for a in addresses if 'name' in a}
    
    matched_groups = []
    
    for group in groups:
        try:
            group_name = group.get('name', '<no-name>')
            members = group.get('member', [])
            
            for member in members:
                # Member can be dict or string
                if isinstance(member, dict):
                    member_name = member.get('name')
                else:
                    member_name = str(member)
                
                # Check if member address contains target IP
                addr = addr_lookup.get(member_name)
                if addr and ip_in_address_object(target_ip, addr):
                    matched_groups.append(group_name)
                    break  # Found in this group, move to next
        
        except Exception as e:
            logger.warning(f"Error processing group {group.get('name')}: {e}")
            continue
    
    return matched_groups


# ==================== Data Export ====================
@handle_errors(error_handler, {"phase": "phase2", "operation": "export"})
def export_fortigate_data(api: FortigateAPIHelper) -> Tuple[List[Dict], List[Dict], List[str]]:
    """
    Export addresses and groups with error handling
    Returns (addresses, groups, errors)
    """
    addresses = []
    groups = []
    errors = []
    
    # Ensure connection
    try:
        api.ensure_connection()
    except Exception as e:
        errors.append(f"Connection failed: {str(e)}")
        return addresses, groups, errors
    
    # Fetch addresses
    print("📥 Fetching Address Objects...")
    try:
        addr_response = api.get('firewall/address')
        addresses = addr_response.get('results', [])
        logger.info(f"Fetched {len(addresses)} addresses")
        print(f"   ✅ Found {len(addresses)} addresses")
    except Exception as e:
        error_msg = f"Failed to fetch addresses: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
        print(f"   ❌ {error_msg}")
    
    # Fetch groups
    print("📥 Fetching Address Groups...")
    try:
        grp_response = api.get('firewall/addrgrp')
        groups = grp_response.get('results', [])
        logger.info(f"Fetched {len(groups)} groups")
        print(f"   ✅ Found {len(groups)} groups")
    except Exception as e:
        error_msg = f"Failed to fetch groups: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
        print(f"   ❌ {error_msg}")
    
    return addresses, groups, errors


# ==================== Results Display ====================
def display_results(addresses: List[Dict], groups: List[Dict],
                    duplicates: Dict, ip_search_results: Dict,
                    errors: List[str]):
    """Display phase 2 results"""
    print("\n" + "="*60)
    print("           Phase 2 Analysis Results")
    print("="*60)
    print(f"Total Addresses   : {len(addresses)}")
    print(f"Total Groups      : {len(groups)}")
    print(f"Duplicate Objects : {len(duplicates)}")
    print(f"IPs Searched      : {len(ip_search_results)}")
    
    if errors:
        print(f"\n⚠️  Errors: {len(errors)}")
    
    print("="*60)
    
    # Duplicates
    if duplicates:
        print("\n🔍 Duplicate Address Objects:")
        for key, names in duplicates.items():
            print(f"\n  {key}")
            for name in names:
                print(f"    • {name}")
    else:
        print("\n✅ No duplicates found")
    
    # IP Search Results
    if ip_search_results:
        print("\n🔍 IP Search Results:")
        for ip, result in ip_search_results.items():
            count = result.get('count', 0)
            groups_found = result.get('matched_groups', [])
            
            print(f"\n  📍 {ip}: {count} group(s)")
            if groups_found:
                for group in groups_found:
                    print(f"      • {group}")
            else:
                print(f"      (Not found in any group)")
    
    # Errors
    if errors:
        print("\n❌ Errors encountered:")
        for err in errors:
            print(f"  • {err}")
    
    print()


# ==================== Save Results ====================
def save_results(config: Dict, addresses: List[Dict], groups: List[Dict],
                duplicates: Dict, ip_search: Dict, errors: List[str]) -> bool:
    """Save results to JSON with backup"""
    output = {
        "phase": 2,
        "timestamp": error_handler.errors[-1]['timestamp'] if error_handler.errors else None,
        "fortigate": {
            "ip": config['ip'],
            "vdom": config['vdom']
        },
        "summary": {
            "total_addresses": len(addresses),
            "total_groups": len(groups),
            "duplicate_count": len(duplicates),
            "ips_searched": len(ip_search),
            "errors": len(errors)
        },
        "duplicates": duplicates,
        "ip_search": ip_search,
        "errors": errors
    }
    
    try:
        # Backup existing file
        if RESULT_FILE.exists():
            recovery.backup_state("phase2_result", {
                "previous_file": str(RESULT_FILE)
            })
        
        # Save new results
        with open(RESULT_FILE, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to {RESULT_FILE}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        print(f"\n⚠️  Warning: Could not save results: {e}")
        return False


# ==================== Main Execution ====================
def load_config() -> Dict:
    """Load configuration with validation"""
    load_dotenv()
    
    ip = os.getenv("FORTIGATE_IP")
    token = os.getenv("FORTIGATE_TOKEN")
    vdom = os.getenv("FORTIGATE_VDOM", "root")
    protocol = os.getenv("FORTIGATE_PROTOCOL", "http")
    
    try:
        validator.validate_non_empty(ip, "FORTIGATE_IP")
        validator.validate_non_empty(token, "FORTIGATE_TOKEN")
    except ValidationError as e:
        error_handler.log_error(e, {"phase": "phase2", "operation": "config"})
        raise
    
    return {
        "ip": ip,
        "token": token,
        "vdom": vdom,
        "protocol": protocol
    }


def main() -> int:
    """Main execution with comprehensive error handling"""
    print("\n" + "="*60)
    print("   Phase 2: IP Search & Duplicate Detection (Enhanced)")
    print("="*60 + "\n")
    
    # Load config
    try:
        config = load_config()
    except ValidationError:
        print("\n❌ Configuration error. Check .env file.")
        return 1
    except Exception as e:
        print(f"\n❌ Configuration error: {e}")
        return 1
    
    # Initialize API
    base_url = f"{config['protocol']}://{config['ip']}/api/v2/cmdb/"
    
    try:
        api = FortigateAPIHelper(
            base_url=base_url,
            token=config['token'],
            vdom=config['vdom'],
            error_handler=error_handler
        )
    except Exception as e:
        print(f"\n❌ API initialization failed: {e}")
        return 1
    
    # Test connection
    print("🔌 Testing connection...")
    if not api.test_connection():
        print("❌ Connection test failed")
        return 1
    print("✅ Connection successful\n")
    
    # Export data
    addresses, groups, export_errors = export_fortigate_data(api)
    
    if not addresses and not groups:
        print("\n❌ No data could be exported")
        return 1
    
    # Find duplicates
    print("\n🔍 Analyzing for duplicates...")
    try:
        duplicates = find_duplicates(addresses)
        logger.info(f"Found {len(duplicates)} duplicate sets")
        print(f"   ✅ Analysis complete: {len(duplicates)} duplicate(s) found")
    except Exception as e:
        logger.error(f"Duplicate detection failed: {e}")
        print(f"   ❌ Duplicate detection failed: {e}")
        duplicates = {}
    
    # Get IP search input
    print("\n" + "="*60)
    print("IP Search")
    print("="*60)
    print("Enter IPs to search (comma/space separated)")
    print("Or use @filename to load from file")
    print("Example: 192.168.1.10, 192.168.1.11")
    print("Example: @ip_list.txt")
    
    raw_input = input("\nIPs: ").strip()
    
    if not raw_input:
        print("\nℹ️  No IPs provided for search. Skipping IP search.")
        ip_search_results = {}
    else:
        # Parse IP input
        ip_list, parse_error = normalize_ip_list_input(raw_input)
        
        if parse_error:
            print(f"\n❌ {parse_error}")
            return 1
        
        # Validate IPs
        valid_ips, invalid_ips = validate_ip_list(ip_list)
        
        if invalid_ips:
            print(f"\n⚠️  Invalid IPs (skipped): {', '.join(invalid_ips)}")
        
        if not valid_ips:
            print("\n❌ No valid IPs to search")
            return 1
        
        print(f"\n🔍 Searching {len(valid_ips)} IP(s)...")
        
        # Search for each IP
        ip_search_results = {}
        for ip in valid_ips:
            try:
                matched_groups = find_groups_with_ip(groups, addresses, ip)
                ip_search_results[ip] = {
                    "matched_groups": matched_groups,
                    "count": len(matched_groups)
                }
                logger.info(f"IP {ip}: found in {len(matched_groups)} groups")
            except Exception as e:
                logger.error(f"Search failed for IP {ip}: {e}")
                ip_search_results[ip] = {
                    "matched_groups": [],
                    "count": 0,
                    "error": str(e)
                }
        
        print("   ✅ Search complete")
    
    # Display results
    display_results(addresses, groups, duplicates, 
                   ip_search_results, export_errors)
    
    # Save results
    print(f"💾 Saving results to {RESULT_FILE}...")
    if save_results(config, addresses, groups, duplicates, 
                   ip_search_results, export_errors):
        print(f"✅ Results saved successfully\n")
        return 0
    else:
        print(f"⚠️  Results could not be saved\n")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in Phase 2")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        # Cleanup
        try:
            recovery.cleanup_old_backups(keep_last=10)
        except:
            pass
    
    sys.exit(exit_code)