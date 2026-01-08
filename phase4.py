#!/usr/bin/env python3
"""
Phase 4 v2.0 - Multi-VIP Creation with VIP Groups and Policies
Enhanced with error handling, validation, and rollback capability
"""

import os
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime
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
logger = setup_syslog_logger("phase4")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = RESULT_DIR / "phase4_lab.json"


# ==================== Input Helpers ====================
def ask(prompt: str, default: str = None) -> str:
    """Prompt for user input with optional default"""
    if default:
        full = f"{prompt} [{default}]: "
    else:
        full = f"{prompt}: "
    val = input(full).strip()
    return val if val else (default or "")


def split_names(s: str) -> List[str]:
    """Split comma-separated names"""
    return [x.strip() for x in s.split(",") if x.strip()] if s else []


# ==================== Validation ====================
def validate_vip_config(vip_name: str, internal_ip: str, ext_ip: str,
                       port: int) -> Tuple[bool, Optional[str]]:
    """Validate VIP configuration"""
    try:
        # Name validation
        validator.validate_non_empty(vip_name, "VIP name")
        if len(vip_name) > 35:
            raise ValidationError("VIP name too long (max 35 characters)")
        if not vip_name.replace('_', '').replace('-', '').isalnum():
            raise ValidationError("VIP name must be alphanumeric (with _ or -)")
        
        # IP validation
        validator.validate_ip(internal_ip)
        validator.validate_ip(ext_ip)
        
        # Port validation
        if port:
            validator.validate_port(port)
        
        return True, None
    
    except ValidationError as e:
        error_handler.log_error(e, {
            "phase": "phase4",
            "operation": "vip_validation",
            "vip_name": vip_name
        })
        return False, str(e)


def validate_policy_config(policy_name: str, srcintf: List[str],
                          dstintf: List[str], service: List[str]) -> Tuple[bool, Optional[str]]:
    """Validate policy configuration"""
    try:
        validator.validate_non_empty(policy_name, "Policy name")
        
        if not srcintf:
            raise ValidationError("Source interfaces cannot be empty")
        if not dstintf:
            raise ValidationError("Destination interfaces cannot be empty")
        if not service:
            raise ValidationError("Services cannot be empty")
        
        return True, None
    
    except ValidationError as e:
        error_handler.log_error(e, {
            "phase": "phase4",
            "operation": "policy_validation"
        })
        return False, str(e)


# ==================== VIP Operations ====================
@handle_errors(error_handler, {"phase": "phase4", "operation": "vip_creation"})
def create_vip(api: FortigateAPIHelper, vip_name: str, ext_ip: str,
               internal_ip: str, extintf: str, port: Optional[int] = None) -> Dict:
    """Create a single VIP with error handling"""
    result = {
        "vip_name": vip_name,
        "success": False,
        "status": "unknown"
    }
    
    # Check if exists
    try:
        if api.object_exists("firewall/vip", vip_name):
            result["success"] = True
            result["status"] = "exists"
            logger.info(f"VIP {vip_name} already exists")
            print(f"   ℹ️  VIP '{vip_name}' already exists")
            return result
    except Exception as e:
        logger.warning(f"Could not check VIP existence: {e}")
    
    # Prepare payload
    payload = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [{"range": f"{internal_ip}-{internal_ip}"}],
        "portforward": "disable",
        "arp-reply": "enable"
    }
    
    # Add port forwarding if specified
    if port:
        payload.update({
            "portforward": "enable",
            "protocol": "tcp",
            "extport": str(port),
            "mappedport": str(port)
        })
    
    # Backup point
    backup_file = recovery.backup_state("vip_creation", {
        "vip_name": vip_name,
        "payload": payload
    })
    
    try:
        logger.info(f"Creating VIP: {vip_name}")
        print(f"   🔨 Creating VIP '{vip_name}'...")
        
        response = api.post("firewall/vip", payload)
        
        if isinstance(response, dict) and response.get("status") == "success":
            result["success"] = True
            result["status"] = "created"
            result["response"] = response
            logger.info(f"✅ VIP created: {vip_name}")
            print(f"   ✅ VIP '{vip_name}' created")
        else:
            result["status"] = "failed"
            result["error"] = response
            logger.error(f"VIP creation failed: {response}")
            print(f"   ❌ VIP creation failed")
        
        return result
    
    except APIError as e:
        result["error"] = str(e)
        result["error_details"] = e.to_dict()
        logger.error(f"API error creating VIP {vip_name}: {e}")
        print(f"   ❌ API error: {e.message}")
        return result
    
    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error creating VIP {vip_name}")
        print(f"   ❌ Error: {e}")
        return result


@handle_errors(error_handler, {"phase": "phase4", "operation": "vip_group"})
def create_vip_group(api: FortigateAPIHelper, group_name: str,
                     interface: str, vip_members: List[str]) -> Dict:
    """Create or update VIP group"""
    result = {
        "group_name": group_name,
        "success": False,
        "operation": "unknown"
    }
    
    # Check if group exists
    group_exists = api.object_exists("firewall/vipgrp", group_name)
    
    # Backup
    if group_exists:
        try:
            existing = api.get(f"firewall/vipgrp/{group_name}")
            recovery.backup_state("vip_group_update", {
                "group_name": group_name,
                "existing": existing
            })
        except Exception as e:
            logger.warning(f"Could not backup VIP group: {e}")
    
    # Prepare payload
    payload = {
        "name": group_name,
        "interface": interface,
        "member": [{"name": vip} for vip in vip_members],
        "comment": "Auto-generated by Phase 4"
    }
    
    try:
        if group_exists:
            # Update existing group
            logger.info(f"Updating VIP group: {group_name}")
            print(f"   🔨 Updating VIP group '{group_name}'...")
            response = api.put(f"firewall/vipgrp/{group_name}", payload)
            result["operation"] = "updated"
        else:
            # Create new group
            logger.info(f"Creating VIP group: {group_name}")
            print(f"   🔨 Creating VIP group '{group_name}'...")
            response = api.post("firewall/vipgrp", payload)
            result["operation"] = "created"
        
        if isinstance(response, dict) and response.get("status") == "success":
            result["success"] = True
            result["response"] = response
            result["members"] = vip_members
            logger.info(f"✅ VIP group {result['operation']}: {group_name}")
            print(f"   ✅ VIP group {result['operation']}")
        else:
            result["error"] = response
            logger.error(f"VIP group operation failed: {response}")
            print(f"   ❌ VIP group operation failed")
        
        return result
    
    except APIError as e:
        result["error"] = str(e)
        result["error_details"] = e.to_dict()
        logger.error(f"API error with VIP group {group_name}: {e}")
        print(f"   ❌ API error: {e.message}")
        return result
    
    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error with VIP group {group_name}")
        print(f"   ❌ Error: {e}")
        return result


# ==================== Policy Operations ====================
@handle_errors(error_handler, {"phase": "phase4", "operation": "policy_creation"})
def create_policy(api: FortigateAPIHelper, policy_name: str, srcintf: List[str],
                 dstintf: List[str], srcaddr: List[str], dstaddr: List[str],
                 service: List[str], action: str = "accept",
                 schedule: str = "always", logtraffic: str = "all",
                 nat: str = "disable") -> Dict:
    """Create firewall policy with error handling"""
    result = {
        "policy_name": policy_name,
        "success": False,
        "status": "unknown"
    }
    
    # Check if policy exists (by name)
    try:
        # Search for policy by name
        policies = api.get("firewall/policy").get("results", [])
        existing = next((p for p in policies if p.get("name") == policy_name), None)
        
        if existing:
            result["success"] = True
            result["status"] = "exists"
            result["policy_id"] = existing.get("policyid")
            logger.info(f"Policy '{policy_name}' already exists")
            print(f"   ℹ️  Policy '{policy_name}' already exists")
            return result
    except Exception as e:
        logger.warning(f"Could not check policy existence: {e}")
    
    # Prepare payload
    payload = {
        "name": policy_name,
        "srcintf": [{"name": intf} for intf in srcintf],
        "dstintf": [{"name": intf} for intf in dstintf],
        "srcaddr": [{"name": addr} for addr in srcaddr],
        "dstaddr": [{"name": addr} for addr in dstaddr],
        "action": action,
        "schedule": schedule,
        "service": [{"name": svc} for svc in service],
        "logtraffic": logtraffic,
        "nat": nat
    }
    
    # Backup
    backup_file = recovery.backup_state("policy_creation", {
        "policy_name": policy_name,
        "payload": payload
    })
    
    try:
        logger.info(f"Creating policy: {policy_name}")
        print(f"   🔨 Creating policy '{policy_name}'...")
        
        response = api.post("firewall/policy", payload)
        
        if isinstance(response, dict) and response.get("status") == "success":
            result["success"] = True
            result["status"] = "created"
            result["policy_id"] = response.get("mkey")
            result["response"] = response
            logger.info(f"✅ Policy created: {policy_name}")
            print(f"   ✅ Policy '{policy_name}' created")
        else:
            result["status"] = "failed"
            result["error"] = response
            logger.error(f"Policy creation failed: {response}")
            print(f"   ❌ Policy creation failed")
        
        return result
    
    except APIError as e:
        result["error"] = str(e)
        result["error_details"] = e.to_dict()
        logger.error(f"API error creating policy: {e}")
        print(f"   ❌ API error: {e.message}")
        return result
    
    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error creating policy")
        print(f"   ❌ Error: {e}")
        return result


# ==================== Rollback ====================
def rollback_vips(api: FortigateAPIHelper, vip_names: List[str]) -> int:
    """Rollback created VIPs"""
    print("\n🔄 Rolling back VIPs...")
    success_count = 0
    
    for vip_name in vip_names:
        try:
            api.delete(f"firewall/vip/{vip_name}")
            logger.info(f"Rolled back VIP: {vip_name}")
            print(f"   ✅ Removed VIP '{vip_name}'")
            success_count += 1
        except Exception as e:
            logger.error(f"Failed to rollback VIP {vip_name}: {e}")
            print(f"   ❌ Failed to remove VIP '{vip_name}': {e}")
    
    return success_count


def rollback_vip_group(api: FortigateAPIHelper, group_name: str) -> bool:
    """Rollback VIP group"""
    try:
        print(f"\n🔄 Rolling back VIP group '{group_name}'...")
        api.delete(f"firewall/vipgrp/{group_name}")
        logger.info(f"Rolled back VIP group: {group_name}")
        print(f"   ✅ Removed VIP group")
        return True
    except Exception as e:
        logger.error(f"Failed to rollback VIP group: {e}")
        print(f"   ❌ Failed to remove VIP group: {e}")
        return False


# ==================== Main Execution ====================
def load_config() -> Dict:
    """Load configuration"""
    load_dotenv()
    
    ip = os.getenv("FORTIGATE_IP")
    token = os.getenv("FORTIGATE_TOKEN")
    vdom = os.getenv("FORTIGATE_VDOM", "root")
    protocol = os.getenv("FORTIGATE_PROTOCOL", "http")
    
    try:
        validator.validate_non_empty(ip, "FORTIGATE_IP")
        validator.validate_non_empty(token, "FORTIGATE_TOKEN")
    except ValidationError as e:
        error_handler.log_error(e)
        raise
    
    return {"ip": ip, "token": token, "vdom": vdom, "protocol": protocol}


def get_vip_configurations() -> List[Dict]:
    """Get VIP configurations from user"""
    print("\n" + "="*60)
    print("VIP Configuration")
    print("="*60)
    
    wan_if = ask("WAN Interface (extintf)", "port2")
    lan_if = ask("LAN Interface (for policy dstintf)", "port4")
    ext_ip = ask("External IP on WAN (extip)", "10.8.10.1")
    
    # Validate external IP
    try:
        validator.validate_ip(ext_ip)
    except ValidationError as e:
        raise ValidationError(f"Invalid external IP: {e}")
    
    print("\nℹ️  Enter internal IPs for each service:")
    print("   (Leave empty to skip that service)")
    
    vips = []
    
    # HTTP
    http_ip = ask("  HTTP service (port 80)", "192.168.1.10")
    if http_ip:
        valid, error = validate_vip_config("VIP_HTTP", http_ip, ext_ip, 80)
        if valid:
            vips.append({
                "name": "VIP_HTTP",
                "ip": http_ip,
                "port": 80,
                "extip": ext_ip,
                "extintf": wan_if
            })
        else:
            print(f"   ⚠️  Skipping HTTP VIP: {error}")
    
    # HTTPS
    https_ip = ask("  HTTPS service (port 443)", "192.168.1.11")
    if https_ip:
        valid, error = validate_vip_config("VIP_HTTPS", https_ip, ext_ip, 443)
        if valid:
            vips.append({
                "name": "VIP_HTTPS",
                "ip": https_ip,
                "port": 443,
                "extip": ext_ip,
                "extintf": wan_if
            })
        else:
            print(f"   ⚠️  Skipping HTTPS VIP: {error}")
    
    # SSH
    ssh_ip = ask("  SSH service (port 22)", "192.168.1.12")
    if ssh_ip:
        valid, error = validate_vip_config("VIP_SSH", ssh_ip, ext_ip, 22)
        if valid:
            vips.append({
                "name": "VIP_SSH",
                "ip": ssh_ip,
                "port": 22,
                "extip": ext_ip,
                "extintf": wan_if
            })
        else:
            print(f"   ⚠️  Skipping SSH VIP: {error}")
    
    if not vips:
        raise ValidationError("No valid VIPs configured")
    
    return vips, wan_if, lan_if


def get_policy_configuration(vip_group_name: str, wan_if: str, 
                            lan_if: str) -> Dict:
    """Get policy configuration from user"""
    print("\n" + "="*60)
    print("Firewall Policy Configuration")
    print("="*60)
    
    policy_name = ask("Policy name", "AUTO_PUBLISH_POLICY")
    srcintf = split_names(ask("Source interfaces (comma-separated)", wan_if))
    dstintf = split_names(ask("Destination interfaces (comma-separated)", lan_if))
    srcaddr = split_names(ask("Source addresses (comma-separated)", "all"))
    dstaddr = split_names(ask("Destination addresses (comma-separated)", vip_group_name))
    action = ask("Action (accept/deny)", "accept")
    schedule = ask("Schedule", "always")
    service = split_names(ask("Service(s) comma-separated", "ALL"))
    logtraffic = ask("Logtraffic (all/utm/disable)", "all")
    nat = ask("NAT (enable/disable)", "disable")
    
    # Validate
    valid, error = validate_policy_config(policy_name, srcintf, dstintf, service)
    if not valid:
        raise ValidationError(f"Invalid policy configuration: {error}")
    
    return {
        "name": policy_name,
        "srcintf": srcintf,
        "dstintf": dstintf,
        "srcaddr": srcaddr,
        "dstaddr": dstaddr,
        "action": action,
        "schedule": schedule,
        "service": service,
        "logtraffic": logtraffic,
        "nat": nat
    }


def save_results(report: Dict) -> bool:
    """Save results to JSON"""
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        logger.info(f"Results saved to {OUTPUT_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        return False


def main() -> int:
    """Main execution"""
    print("\n" + "="*60)
    print("   Phase 4: Multi-VIP Lab (Enhanced)")
    print("="*60)
    
    # Load config
    try:
        config = load_config()
    except ValidationError:
        print("\n❌ Configuration error. Check .env file.")
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
    print("\n🔌 Testing connection...")
    if not api.test_connection():
        print("❌ Connection test failed")
        return 1
    print("✅ Connection successful")
    
    # Get configurations
    try:
        vip_configs, wan_if, lan_if = get_vip_configurations()
    except (ValidationError, KeyboardInterrupt) as e:
        print(f"\n⚠️  {e if not isinstance(e, KeyboardInterrupt) else 'Cancelled'}")
        return 1
    
    vip_group_name = ask("\nVIP Group Name", "VIP_PUBLISH_GROUP")
    
    try:
        policy_config = get_policy_configuration(vip_group_name, wan_if, lan_if)
    except (ValidationError, KeyboardInterrupt) as e:
        print(f"\n⚠️  {e if not isinstance(e, KeyboardInterrupt) else 'Cancelled'}")
        return 1
    
    # Report structure
    report = {
        "phase": 4,
        "timestamp": datetime.now().isoformat(),
        "vips": [],
        "vip_group": {},
        "policy": {},
        "overall_success": False
    }
    
    created_vips = []
    
    # Create VIPs
    print("\n" + "="*60)
    print("Creating VIPs...")
    print("="*60)
    
    for vip_config in vip_configs:
        result = create_vip(
            api,
            vip_config["name"],
            vip_config["extip"],
            vip_config["ip"],
            vip_config["extintf"],
            vip_config.get("port")
        )
        report["vips"].append(result)
        
        if result.get("success"):
            created_vips.append(vip_config["name"])
    
    if not created_vips:
        print("\n❌ No VIPs were created. Aborting.")
        save_results(report)
        return 1
    
    # Create/Update VIP Group
    print("\n" + "="*60)
    print("Managing VIP Group...")
    print("="*60)
    
    vip_group_result = create_vip_group(api, vip_group_name, wan_if, created_vips)
    report["vip_group"] = vip_group_result
    
    # Create Policy
    print("\n" + "="*60)
    print("Creating Firewall Policy...")
    print("="*60)
    
    policy_result = create_policy(
        api,
        policy_config["name"],
        policy_config["srcintf"],
        policy_config["dstintf"],
        policy_config["srcaddr"],
        policy_config["dstaddr"],
        policy_config["service"],
        policy_config["action"],
        policy_config["schedule"],
        policy_config["logtraffic"],
        policy_config["nat"]
    )
    report["policy"] = policy_result
    
    # Determine overall success
    vips_ok = all(v.get("success") for v in report["vips"])
    group_ok = vip_group_result.get("success")
    policy_ok = policy_result.get("success")
    
    report["overall_success"] = vips_ok and group_ok and policy_ok
    
    # Save results
    save_results(report)
    
    # Summary
    print("\n" + "="*60)
    print("   Phase 4 Summary")
    print("="*60)
    print(f"VIPs Created:     {len(created_vips)}/{len(vip_configs)}")
    print(f"VIP Group:        {'✅' if group_ok else '❌'} {vip_group_result.get('operation', 'failed')}")
    print(f"Policy:           {'✅' if policy_ok else '❌'} {policy_result.get('status', 'failed')}")
    print(f"Overall:          {'✅ SUCCESS' if report['overall_success'] else '⚠️  PARTIAL'}")
    print(f"\n💾 Results saved to: {OUTPUT_FILE}")
    print("="*60 + "\n")
    
    # Rollback option if partial failure
    if not report["overall_success"] and created_vips:
        rollback = input("Some operations failed. Rollback? [y/N]: ").strip().lower()
        if rollback == 'y':
            if policy_ok:
                print("\n⚠️  Cannot rollback policy automatically")
            if group_ok:
                rollback_vip_group(api, vip_group_name)
            rollback_vips(api, created_vips)
            print("\n✅ Rollback completed")
    
    return 0 if report["overall_success"] else 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in Phase 4")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        recovery.cleanup_old_backups(keep_last=10)
    
    sys.exit(exit_code)