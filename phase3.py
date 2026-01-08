#!/usr/bin/env python3
"""
Phase 3 v2.0 - VIP Creation & Policy Update
Enhanced with error handling, validation, and rollback capability
"""

import os
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple
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
logger = setup_syslog_logger("phase3")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

RESULT_FOLDER = Path("result_json")
RESULT_FOLDER.mkdir(exist_ok=True)
RESULT_FILE = RESULT_FOLDER / "phase3_result.json"


# ==================== Validation ====================
def validate_vip_inputs(vip_name: str, ext_ip: str, mapped_ip: str, 
                        extintf: str) -> Tuple[bool, Optional[str]]:
    """Validate all VIP inputs"""
    try:
        # Name validation
        validator.validate_non_empty(vip_name, "VIP name")
        if len(vip_name) > 35:
            raise ValidationError("VIP name too long (max 35 characters)")
        if not vip_name.replace('_', '').replace('-', '').isalnum():
            raise ValidationError("VIP name must be alphanumeric (with _ or -)")
        
        # IP validation
        validator.validate_ip(ext_ip)
        validator.validate_ip(mapped_ip)
        
        # Interface validation
        validator.validate_non_empty(extintf, "External interface")
        
        return True, None
    
    except ValidationError as e:
        error_handler.log_error(e, {
            "phase": "phase3",
            "operation": "input_validation"
        })
        return False, str(e)


def validate_policy_id(policy_id: int) -> Tuple[bool, Optional[str]]:
    """Validate policy ID"""
    try:
        if policy_id <= 0:
            raise ValidationError(f"Policy ID must be positive, got {policy_id}")
        return True, None
    except ValidationError as e:
        error_handler.log_error(e, {
            "phase": "phase3",
            "operation": "policy_validation"
        })
        return False, str(e)


# ==================== VIP Operations ====================
@handle_errors(error_handler, {"phase": "phase3", "operation": "vip_creation"})
def create_vip(api: FortigateAPIHelper, vip_name: str, ext_ip: str, 
               mapped_ip: str, extintf: str = "any") -> Dict:
    """
    Create VIP with comprehensive error handling
    
    Returns:
        Dict with success status and details
    """
    result = {
        "success": False,
        "operation": "create_vip",
        "vip_name": vip_name,
        "timestamp": datetime.now().isoformat()
    }
    
    # Check if VIP already exists
    try:
        if api.object_exists("firewall/vip", vip_name):
            result["success"] = True
            result["status"] = "already_exists"
            result["message"] = f"VIP '{vip_name}' already exists"
            logger.info(f"VIP {vip_name} already exists")
            print(f"ℹ️  VIP '{vip_name}' already exists")
            return result
    except Exception as e:
        logger.warning(f"Could not check VIP existence: {e}")
        # Continue anyway
    
    # Prepare VIP data
    vip_data = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [{"range": f"{mapped_ip}-{mapped_ip}"}],
        "arp-reply": "enable"
    }
    
    # Create backup point
    backup_file = recovery.backup_state("vip_creation", {
        "vip_name": vip_name,
        "vip_data": vip_data,
        "operation": "create"
    })
    
    try:
        logger.info(f"Creating VIP: {vip_name}")
        print(f"🔨 Creating VIP '{vip_name}'...")
        
        resp = api.post("firewall/vip", vip_data)
        
        if isinstance(resp, dict) and resp.get("status") == "success":
            result["success"] = True
            result["status"] = "created"
            result["message"] = f"VIP '{vip_name}' created successfully"
            result["response"] = resp
            logger.info(f"✅ VIP created: {vip_name}")
            print(f"✅ VIP '{vip_name}' created successfully")
        else:
            result["status"] = "failed"
            result["message"] = "FortiGate did not return success"
            result["response"] = resp
            logger.error(f"VIP creation failed: {resp}")
            print(f"❌ VIP creation failed")
        
        return result
    
    except APIError as e:
        result["error"] = str(e)
        result["error_details"] = e.to_dict()
        logger.error(f"API error creating VIP: {e}")
        print(f"❌ API error: {e.message}")
        return result
    
    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error creating VIP: {e}")
        print(f"❌ Unexpected error: {e}")
        return result


# ==================== Policy Operations ====================
@handle_errors(error_handler, {"phase": "phase3", "operation": "policy_update"})
def update_policy(api: FortigateAPIHelper, policy_id: int, 
                  vip_name: str) -> Dict:
    """
    Update firewall policy with VIP in destination
    
    Returns:
        Dict with success status and details
    """
    result = {
        "success": False,
        "operation": "update_policy",
        "policy_id": policy_id,
        "vip_name": vip_name,
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        # Get existing policy
        logger.info(f"Fetching policy {policy_id}")
        print(f"📋 Fetching policy {policy_id}...")
        
        policy_resp = api.get(f"firewall/policy/{policy_id}")
        
        if not policy_resp or "results" not in policy_resp or not policy_resp["results"]:
            error = ValidationError(f"Policy {policy_id} not found")
            error_handler.log_error(error, {"policy_id": policy_id})
            result["error"] = "Policy not found"
            result["message"] = f"Policy ID {policy_id} does not exist"
            print(f"❌ Policy {policy_id} not found")
            return result
        
        policy = policy_resp["results"][0]
        
        # Backup current policy
        backup_file = recovery.backup_state("policy_update", {
            "policy_id": policy_id,
            "original_policy": policy,
            "vip_to_add": vip_name
        })
        logger.info(f"Policy backup created: {backup_file}")
        
        # Prepare destination addresses
        dstaddr = policy.get("dstaddr", [])
        if not isinstance(dstaddr, list):
            dstaddr = []
        
        # Check if VIP already in policy
        vip_exists_in_policy = any(
            addr.get("name") == vip_name for addr in dstaddr
        )
        
        if vip_exists_in_policy:
            result["success"] = True
            result["status"] = "already_attached"
            result["message"] = f"VIP '{vip_name}' already in policy {policy_id}"
            logger.info(f"VIP already in policy {policy_id}")
            print(f"ℹ️  VIP '{vip_name}' already attached to policy")
            return result
        
        # Add VIP to destination addresses
        dstaddr.append({"name": vip_name})
        
        update_data = {
            "dstaddr": dstaddr,
            "nat": policy.get("nat", "disable")
        }
        
        # Update policy
        logger.info(f"Updating policy {policy_id} with VIP {vip_name}")
        print(f"🔨 Attaching VIP to policy {policy_id}...")
        
        resp = api.put(f"firewall/policy/{policy_id}", update_data)
        
        if isinstance(resp, dict) and resp.get("status") == "success":
            result["success"] = True
            result["status"] = "updated"
            result["message"] = f"Policy {policy_id} updated with VIP '{vip_name}'"
            result["response"] = resp
            logger.info(f"✅ Policy updated: {policy_id}")
            print(f"✅ Policy {policy_id} updated successfully")
        else:
            result["status"] = "failed"
            result["message"] = "FortiGate did not return success"
            result["response"] = resp
            logger.error(f"Policy update failed: {resp}")
            print(f"❌ Policy update failed")
        
        return result
    
    except APIError as e:
        result["error"] = str(e)
        result["error_details"] = e.to_dict()
        logger.error(f"API error updating policy: {e}")
        print(f"❌ API error: {e.message}")
        return result
    
    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error updating policy: {e}")
        print(f"❌ Unexpected error: {e}")
        return result


# ==================== Rollback ====================
def rollback_vip(api: FortigateAPIHelper, vip_name: str) -> bool:
    """Rollback VIP creation"""
    try:
        print(f"\n🔄 Rolling back VIP '{vip_name}'...")
        api.delete(f"firewall/vip/{vip_name}")
        logger.info(f"Rolled back VIP: {vip_name}")
        print(f"✅ VIP '{vip_name}' removed")
        return True
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        print(f"❌ Rollback failed: {e}")
        return False


def rollback_policy(api: FortigateAPIHelper, backup_data: Dict) -> bool:
    """Rollback policy to previous state"""
    try:
        policy_id = backup_data.get("policy_id")
        original = backup_data.get("original_policy")
        
        if not policy_id or not original:
            return False
        
        print(f"\n🔄 Rolling back policy {policy_id}...")
        
        # Restore original dstaddr
        update_data = {
            "dstaddr": original.get("dstaddr", []),
            "nat": original.get("nat", "disable")
        }
        
        api.put(f"firewall/policy/{policy_id}", update_data)
        logger.info(f"Rolled back policy: {policy_id}")
        print(f"✅ Policy {policy_id} restored")
        return True
    
    except Exception as e:
        logger.error(f"Policy rollback failed: {e}")
        print(f"❌ Policy rollback failed: {e}")
        return False


# ==================== Summary Display ====================
def print_summary(vip_name: str, ext_ip: str, mapped_ip: str, policy_id: int,
                 vip_result: Dict, policy_result: Dict):
    """Print operation summary"""
    vip_icon = "🟢" if vip_result.get("success") else "🔴"
    policy_icon = "🟢" if policy_result.get("success") else "🔴"
    
    print("\n" + "╔" + "═"*58 + "╗")
    print("║" + " "*15 + "Phase 3 Operation Summary" + " "*19 + "║")
    print("╠" + "═"*58 + "╣")
    print(f"║ VIP Name:      {vip_name:<40} ║")
    print(f"║ External IP:   {ext_ip:<40} ║")
    print(f"║ Internal IP:   {mapped_ip:<40} ║")
    print(f"║ Policy ID:     {str(policy_id):<40} ║")
    print("╠" + "═"*58 + "╣")
    print(f"║ VIP Status:    {vip_icon} {vip_result.get('status', 'unknown'):<37} ║")
    print(f"║ Policy Status: {policy_icon} {policy_result.get('status', 'unknown'):<37} ║")
    print("╚" + "═"*58 + "╝")


# ==================== Main Execution ====================
def load_config() -> Dict:
    """Load configuration with validation"""
    load_dotenv()
    
    ip = os.getenv("FORTIGATE_IP")
    token = os.getenv("FORTIGATE_TOKEN")
    vdom = os.getenv("FORTIGATE_VDOM", "root")
    
    try:
        validator.validate_non_empty(ip, "FORTIGATE_IP")
        validator.validate_non_empty(token, "FORTIGATE_TOKEN")
    except ValidationError as e:
        error_handler.log_error(e)
        raise
    
    return {"ip": ip, "token": token, "vdom": vdom}


def get_user_input() -> Dict:
    """Get and validate user input"""
    print("\n📝 Enter VIP Configuration:")
    print("-" * 40)
    
    vip_name = input("VIP name: ").strip()
    ext_ip = input("External IP (extip): ").strip()
    mapped_ip = input("Mapped/Internal IP: ").strip()
    extintf = input("External interface [any]: ").strip() or "any"
    
    # Validate inputs
    valid, error = validate_vip_inputs(vip_name, ext_ip, mapped_ip, extintf)
    if not valid:
        raise ValidationError(f"Invalid input: {error}")
    
    try:
        policy_id = int(input("Firewall Policy ID: ").strip())
        valid, error = validate_policy_id(policy_id)
        if not valid:
            raise ValidationError(f"Invalid policy ID: {error}")
    except ValueError:
        raise ValidationError("Policy ID must be a number")
    
    return {
        "vip_name": vip_name,
        "ext_ip": ext_ip,
        "mapped_ip": mapped_ip,
        "extintf": extintf,
        "policy_id": policy_id
    }


def save_results(vip_result: Dict, policy_result: Dict) -> bool:
    """Save operation results"""
    output = {
        "phase": 3,
        "timestamp": datetime.now().isoformat(),
        "vip_creation": vip_result,
        "policy_update": policy_result,
        "overall_success": vip_result.get("success") and policy_result.get("success")
    }
    
    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, ensure_ascii=False)
        logger.info(f"Results saved to {RESULT_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        print(f"\n⚠️  Warning: Could not save results: {e}")
        return False


def main() -> int:
    """Main execution with error handling"""
    print("\n" + "="*60)
    print("   Phase 3: VIP Creation & Policy Update (Enhanced)")
    print("="*60)
    
    # Load config
    try:
        config = load_config()
    except ValidationError:
        print("\n❌ Configuration error. Check .env file.")
        return 1
    except Exception as e:
        print(f"\n❌ Configuration error: {e}")
        return 1
    
    # Get user input
    try:
        inputs = get_user_input()
    except ValidationError as e:
        print(f"\n❌ {e}")
        return 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Cancelled by user")
        return 130
    except Exception as e:
        print(f"\n❌ Input error: {e}")
        return 1
    
    # Initialize API
    base_url = f"http://{config['ip']}/api/v2/cmdb"
    
    try:
        api = FortigateAPIHelper(
            base_url=base_url,
            token=config["token"],
            vdom=config["vdom"],
            error_handler=error_handler
        )
    except Exception as e:
        print(f"\n❌ API initialization failed: {e}")
        return 1
    
    # Test connection
    print("\n🔌 Testing connection...")
    if not api.test_connection():
        print("❌ Connection failed")
        return 1
    print("✅ Connection successful\n")
    
    # Create VIP
    vip_result = create_vip(
        api,
        inputs["vip_name"],
        inputs["ext_ip"],
        inputs["mapped_ip"],
        inputs["extintf"]
    )
    
    # Update policy (only if VIP creation succeeded)
    if vip_result.get("success"):
        policy_result = update_policy(
            api,
            inputs["policy_id"],
            inputs["vip_name"]
        )
        
        # Rollback VIP if policy update failed
        if not policy_result.get("success"):
            print("\n⚠️  Policy update failed. VIP created but not attached.")
            rollback = input("Rollback VIP creation? [y/N]: ").strip().lower()
            if rollback == 'y':
                rollback_vip(api, inputs["vip_name"])
    else:
        policy_result = {
            "success": False,
            "status": "skipped",
            "message": "Skipped due to VIP creation failure"
        }
        print("\n⚠️  Policy update skipped (VIP creation failed)")
    
    # Display summary
    print_summary(
        inputs["vip_name"],
        inputs["ext_ip"],
        inputs["mapped_ip"],
        inputs["policy_id"],
        vip_result,
        policy_result
    )
    
    # Save results
    save_results(vip_result, policy_result)
    
    # Print final status
    overall_success = vip_result.get("success") and policy_result.get("success")
    
    if overall_success:
        print(f"\n✅ Phase 3 completed successfully")
        print(f"   Results saved to: {RESULT_FILE}\n")
        return 0
    else:
        print(f"\n⚠️  Phase 3 completed with errors")
        print(f"   Results saved to: {RESULT_FILE}\n")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in Phase 3")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        recovery.cleanup_old_backups(keep_last=10)
    
    sys.exit(exit_code)