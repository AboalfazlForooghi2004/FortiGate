#!/usr/bin/env python3
"""
Phase 5 v2.0 - Safe VIP Deletion
Enhanced with comprehensive error handling, dependency checking, and rollback
"""

import os
import json
import sys
import argparse
from typing import List, Dict, Optional, Tuple
from pathlib import Path
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
logger = setup_syslog_logger("phase5")
error_handler = ErrorHandler()
validator = Validator()
recovery = RecoveryManager()

RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = RESULT_DIR / "phase5_report.json"
BACKUP_FILE = RESULT_DIR / "phase5_backup.json"


# ==================== Helper Functions ====================
def yes_no(prompt: str, default: bool = False) -> bool:
    """Prompt yes/no question"""
    suffix = " [Y/n]: " if default else " [y/N]: "
    resp = input(prompt + suffix).strip().lower()
    if not resp:
        return default
    return resp in ("y", "yes")


def safe_get_name(obj) -> str:
    """Safely get name from dict or string"""
    if isinstance(obj, dict):
        return obj.get("name", "<unknown>")
    elif isinstance(obj, str):
        return obj
    return "<unknown>"


# ==================== VIP Operations ====================
# NOTE: No @handle_errors here — this function returns a Tuple and
# must not be wrapped (decorator returns dict on error → unpacking crashes)
def vip_exists(api: FortigateAPIHelper, vip_name: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if VIP exists.
    Returns (exists: bool, vip_config: dict | None)
    """
    try:
        if not api.object_exists("firewall/vip", vip_name):
            return False, None

        resp = api.get(f"firewall/vip/{vip_name}")
        results = resp.get("results", [])

        if results:
            logger.info(f"VIP {vip_name} found")
            return True, results[0]

        return False, None

    except APIError as e:
        if "not found" in str(e).lower():
            return False, None
        logger.error(f"API error checking VIP {vip_name}: {e}")
        return False, None

    except Exception as e:
        logger.error(f"Unexpected error checking VIP {vip_name}: {e}")
        return False, None


# NOTE: No @handle_errors here — result must be iterable (list), not dict
def find_all_vip_references(api: FortigateAPIHelper, vip_name: str) -> List[Dict]:
    """
    Find all references to the VIP in VIP groups and firewall policies.
    Always returns a list (empty on error).
    """
    refs = []

    # Check VIP Groups
    print(f"   🔍 Checking VIP groups...")
    try:
        resp = api.get("firewall/vipgrp")
        for grp in resp.get("results", []):
            members = [safe_get_name(m) for m in grp.get("member", [])]
            if vip_name in members:
                refs.append({
                    "type": "vipgrp",
                    "name": grp.get("name"),
                    "id": grp.get("name")
                })
                logger.info(f"VIP {vip_name} found in VIP group: {grp.get('name')}")
    except Exception as e:
        logger.error(f"Error checking VIP groups: {e}")
        print(f"      ⚠️  Could not check VIP groups: {e}")

    # Check Policies
    print(f"   🔍 Checking firewall policies...")
    try:
        resp = api.get("firewall/policy")
        for pol in resp.get("results", []):
            policy_id = pol.get("policyid")
            policy_name = pol.get("name", f"Policy_{policy_id}")

            # Check dstaddr
            dstaddrs = [safe_get_name(d) for d in pol.get("dstaddr", [])]
            if vip_name in dstaddrs:
                refs.append({
                    "type": "policy_dstaddr",
                    "name": policy_name,
                    "id": policy_id
                })
                logger.info(f"VIP {vip_name} found in policy {policy_id} dstaddr")

            # Check poolname
            poolname = pol.get("poolname", [])
            pool_names = [safe_get_name(p) for p in poolname] if isinstance(poolname, list) else []
            if vip_name in pool_names:
                refs.append({
                    "type": "policy_poolname",
                    "name": policy_name,
                    "id": policy_id
                })
                logger.info(f"VIP {vip_name} found in policy {policy_id} poolname")

    except Exception as e:
        logger.error(f"Error checking policies: {e}")
        print(f"      ⚠️  Could not check policies: {e}")

    return refs


# ==================== Reference Removal ====================
@handle_errors(error_handler, {"phase": "phase5", "operation": "remove_reference"})
def remove_vip_from_group(api: FortigateAPIHelper, group_name: str,
                          vip_name: str, dry_run: bool = False) -> Dict:
    """Remove VIP from VIP group"""
    result = {
        "success": False,
        "group_name": group_name,
        "dry_run": dry_run
    }

    if dry_run:
        result["success"] = True
        result["message"] = "Dry-run mode - no changes made"
        return result

    try:
        grp_resp = api.get(f"firewall/vipgrp/{group_name}")
        grp = grp_resp.get("results", [{}])[0]

        recovery.backup_state("vip_group_modification", {
            "group_name": group_name,
            "original": grp,
            "vip_to_remove": vip_name
        })

        members = [safe_get_name(m) for m in grp.get("member", [])
                   if safe_get_name(m) != vip_name]

        if not members:
            logger.warning(f"VIP group {group_name} will be empty after removal")
            print(f"      ⚠️  VIP group '{group_name}' will be empty")

            if yes_no(f"      Delete empty VIP group '{group_name}'?", False):
                api.delete(f"firewall/vipgrp/{group_name}")
                result["success"] = True
                result["message"] = "Group deleted (was empty)"
                logger.info(f"Deleted empty VIP group: {group_name}")
                return result
            else:
                result["success"] = False
                result["message"] = "User declined to delete empty group"
                return result

        update_data = {
            "interface": grp.get("interface"),
            "member": [{"name": m} for m in members]
        }

        api.put(f"firewall/vipgrp/{group_name}", update_data)
        result["success"] = True
        result["message"] = f"VIP removed from group (remaining: {len(members)})"
        result["remaining_members"] = members
        logger.info(f"Removed VIP from group {group_name}")
        return result

    except APIError as e:
        result["error"] = str(e)
        logger.error(f"Failed to remove VIP from group {group_name}: {e}")
        return result

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error removing VIP from group")
        return result


@handle_errors(error_handler, {"phase": "phase5", "operation": "remove_from_policy"})
def remove_vip_from_policy(api: FortigateAPIHelper, policy_id: int,
                           vip_name: str, ref_type: str,
                           dry_run: bool = False) -> Dict:
    """Remove VIP from policy (dstaddr or poolname)"""
    result = {
        "success": False,
        "policy_id": policy_id,
        "ref_type": ref_type,
        "dry_run": dry_run
    }

    if dry_run:
        result["success"] = True
        result["message"] = "Dry-run mode - no changes made"
        return result

    try:
        pol_resp = api.get(f"firewall/policy/{policy_id}")
        pol = pol_resp.get("results", [{}])[0]

        recovery.backup_state("policy_modification", {
            "policy_id": policy_id,
            "original": pol,
            "vip_to_remove": vip_name,
            "ref_type": ref_type
        })

        if ref_type == "policy_dstaddr":
            dstaddrs = [d for d in pol.get("dstaddr", [])
                        if safe_get_name(d) != vip_name]

            if not dstaddrs:
                logger.warning(f"Policy {policy_id} will have no destination after removal")
                print(f"      ⚠️  Policy {policy_id} will have NO destination addresses")
                result["success"] = False
                result["message"] = "Cannot remove - policy would have no destination"
                return result

            update_data = {"dstaddr": dstaddrs}

        elif ref_type == "policy_poolname":
            poolnames = [p for p in pol.get("poolname", [])
                         if safe_get_name(p) != vip_name]
            update_data = {"poolname": poolnames}

        else:
            result["error"] = f"Unknown ref_type: {ref_type}"
            return result

        api.put(f"firewall/policy/{policy_id}", update_data)
        result["success"] = True
        result["message"] = f"VIP removed from policy {ref_type}"
        logger.info(f"Removed VIP from policy {policy_id} ({ref_type})")
        return result

    except APIError as e:
        result["error"] = str(e)
        logger.error(f"Failed to remove VIP from policy {policy_id}: {e}")
        return result

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error removing VIP from policy")
        return result


def remove_all_references(api: FortigateAPIHelper, vip_name: str,
                          references: List[Dict], dry_run: bool = False) -> List[Dict]:
    """Remove VIP from all references"""
    results = []

    for ref in references:
        ref_type = ref["type"]
        ref_name = ref["name"]

        print(f"   🔨 Removing from {ref_type}: {ref_name}...")

        if ref_type == "vipgrp":
            result = remove_vip_from_group(api, ref_name, vip_name, dry_run)
        elif ref_type in ("policy_dstaddr", "policy_poolname"):
            result = remove_vip_from_policy(api, ref["id"], vip_name, ref_type, dry_run)
        else:
            result = {
                "success": False,
                "error": f"Unknown reference type: {ref_type}"
            }

        results.append({"ref": ref, "result": result})

        if result.get("success"):
            print(f"      ✅ {result.get('message', 'Success')}")
        else:
            print(f"      ❌ {result.get('error', 'Failed')}")

    return results


# ==================== VIP Deletion ====================
@handle_errors(error_handler, {"phase": "phase5", "operation": "vip_deletion"})
def delete_vip(api: FortigateAPIHelper, vip_name: str,
               dry_run: bool = False) -> Dict:
    """Delete VIP from FortiGate"""
    result = {
        "vip_name": vip_name,
        "success": False,
        "dry_run": dry_run
    }

    if dry_run:
        result["success"] = True
        result["message"] = "Dry-run mode - VIP not deleted"
        return result

    try:
        logger.info(f"Deleting VIP: {vip_name}")
        api.delete(f"firewall/vip/{vip_name}")
        result["success"] = True
        result["message"] = f"VIP '{vip_name}' deleted successfully"
        logger.info(f"✅ VIP deleted: {vip_name}")
        return result

    except APIError as e:
        result["error"] = str(e)
        logger.error(f"Failed to delete VIP {vip_name}: {e}")
        return result

    except Exception as e:
        result["error"] = str(e)
        logger.exception(f"Unexpected error deleting VIP {vip_name}")
        return result


# ==================== Main Processing ====================
def process_vip_deletion(api: FortigateAPIHelper, vip_name: str,
                         dry_run: bool = False, force: bool = False) -> Dict:
    """Process deletion of a single VIP"""
    result = {
        "vip_name": vip_name,
        "success": False,
        "vip_existed": False,
        "references_found": 0,
        "references_removed": 0,
        "vip_deleted": False,
        "errors": []
    }

    print(f"\n{'='*60}")
    print(f"Processing VIP: {vip_name}")
    print('='*60)

    # Check if VIP exists — safe tuple unpacking (no @handle_errors on vip_exists)
    print("🔍 Checking VIP existence...")
    exists, vip_config = vip_exists(api, vip_name)

    if not exists:
        result["errors"].append(f"VIP '{vip_name}' does not exist")
        logger.warning(f"VIP {vip_name} not found")
        print(f"   ⚠️  VIP '{vip_name}' does not exist")
        return result

    result["vip_existed"] = True
    print(f"   ✅ VIP found")

    # Backup VIP config
    print("💾 Creating backup...")
    backup_data = {
        "vip_name": vip_name,
        "config": vip_config,
        "timestamp": datetime.now().isoformat()
    }

    backup_file = recovery.backup_state(f"vip_deletion_{vip_name}", backup_data)
    print(f"   ✅ Backup created: {backup_file}")

    # Find references — always returns a list (no @handle_errors on find_all_vip_references)
    print("\n🔍 Finding references...")
    refs = find_all_vip_references(api, vip_name)
    result["references_found"] = len(refs)

    if refs:
        print(f"\n   Found {len(refs)} reference(s):")
        for ref in refs:
            print(f"      • {ref['type']}: {ref['name']}")

        if not force and not dry_run:
            if not yes_no("\n   Remove these references?", False):
                result["errors"].append("User declined to remove references")
                print("\n⚠️  Deletion cancelled")
                return result

        print("\n🔨 Removing references...")
        removal_results = remove_all_references(api, vip_name, refs, dry_run)

        result["references_removed"] = sum(
            1 for r in removal_results if r["result"].get("success")
        )

        if result["references_removed"] < len(refs):
            failed = len(refs) - result["references_removed"]
            result["errors"].append(f"{failed} reference(s) could not be removed")
            print(f"\n⚠️  {failed} reference(s) could not be removed")

            if not force:
                if not yes_no("   Continue with VIP deletion?", False):
                    result["errors"].append("User cancelled due to failed reference removal")
                    return result
    else:
        print("   ✅ No references found")

    # Delete VIP
    print("\n🗑️  Deleting VIP...")
    if not force and not dry_run:
        if not yes_no(f"   Delete VIP '{vip_name}'?", False):
            result["errors"].append("User cancelled VIP deletion")
            print("\n⚠️  VIP deletion cancelled")
            return result

    del_result = delete_vip(api, vip_name, dry_run)
    result["vip_deleted"] = del_result.get("success")

    if del_result.get("success"):
        print(f"   ✅ {del_result.get('message')}")
        result["success"] = True
    else:
        result["errors"].append(del_result.get("error", "Deletion failed"))
        print(f"   ❌ {del_result.get('error', 'Failed')}")

    return result


# ==================== Results ====================
def save_report(report: Dict) -> bool:
    """Save deletion report"""
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"Report saved to {OUTPUT_FILE}")
        return True
    except Exception as e:
        logger.error(f"Failed to save report: {e}")
        return False


def display_summary(report: Dict):
    """Display deletion summary"""
    print("\n" + "="*60)
    print("   Phase 5 Deletion Summary")
    print("="*60)
    print(f"VIPs Processed:          {len(report['vips_processed'])}")
    print(f"VIPs Deleted:            {report['total_vips_deleted']}")
    print(f"References Found:        {report['total_references_found']}")
    print(f"References Removed:      {report['total_references_removed']}")

    if report['errors']:
        print(f"Errors:                  {len(report['errors'])}")

    print("\n" + "="*60)

    if report['vips_processed']:
        print("\nDetailed Results:")
        for vip_result in report['vips_processed']:
            vip_name = vip_result['vip_name']
            success = vip_result.get('success', False)
            icon = "✅" if success else "❌"
            print(f"  {icon} {vip_name}")
            if vip_result.get('errors'):
                for err in vip_result['errors']:
                    print(f"      • {err}")

    print()


# ==================== Main ====================
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


def main() -> int:
    """Main execution"""
    parser = argparse.ArgumentParser(description="Phase 5: Safe VIP Deletion")
    parser.add_argument("vip_names", nargs="*", help="VIP names to delete")
    parser.add_argument("--dry-run", action="store_true", help="Simulate only")
    parser.add_argument("--force", action="store_true", help="Skip confirmations")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("   Phase 5: Safe VIP Deletion (Enhanced)")
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

    # Get VIP names
    if not args.vip_names:
        print("\n" + "="*60)
        print("Available VIPs:")
        print("="*60)
        try:
            vips = api.get("firewall/vip").get("results", [])
            if vips:
                for v in vips:
                    print(f"  • {v.get('name')}")
            else:
                print("  (No VIPs found)")
        except Exception as e:
            logger.error(f"Error listing VIPs: {e}")
            print(f"  ❌ Error: {e}")

        vip_input = input("\nEnter VIP names to delete (space-separated): ").strip()
        if not vip_input:
            print("\n⚠️  No VIPs provided. Exiting.")
            return 0
        args.vip_names = vip_input.split()

    if args.dry_run:
        print("\n🔬 DRY-RUN MODE - No changes will be made")

    # Process each VIP
    report = {
        "phase": 5,
        "timestamp": datetime.now().isoformat(),
        "dry_run": args.dry_run,
        "vips_processed": [],
        "total_vips_deleted": 0,
        "total_references_found": 0,
        "total_references_removed": 0,
        "errors": []
    }

    for vip_name in args.vip_names:
        try:
            result = process_vip_deletion(api, vip_name, args.dry_run, args.force)
            report["vips_processed"].append(result)

            if result.get("success"):
                report["total_vips_deleted"] += 1

            report["total_references_found"] += result.get("references_found", 0)
            report["total_references_removed"] += result.get("references_removed", 0)
            report["errors"].extend(result.get("errors", []))

        except Exception as e:
            logger.exception(f"Failed to process VIP {vip_name}")
            report["errors"].append(f"{vip_name}: {str(e)}")
            print(f"\n❌ Failed to process VIP '{vip_name}': {e}")

    # Save report
    save_report(report)

    # Display summary
    display_summary(report)

    print(f"💾 Report saved to: {OUTPUT_FILE}\n")

    return 0 if report["total_vips_deleted"] == len(args.vip_names) else 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled")
        exit_code = 130
    except Exception as e:
        logger.exception("Fatal error in Phase 5")
        print(f"\n❌ Fatal error: {e}")
        exit_code = 1
    finally:
        recovery.cleanup_old_backups(keep_last=15)

    sys.exit(exit_code)
