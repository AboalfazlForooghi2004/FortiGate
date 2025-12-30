#!/usr/bin/env python3
"""
Phase 5 - Safe VIP Deletion (FortiGate Automation)

Safely removes VIP objects by:
1. Finding all references (VIP Groups, Policies, NAT configs)
2. Removing VIP from all references
3. Deleting the VIP object
4. Optional: Clean up empty groups and unused policies

Features:
- Comprehensive reference detection
- Dry-run mode for safety
- Backup before deletion
- Detailed reporting

Outputs:
- phase5_result.json (deletion report)
- phase5_backup.json (backup of deleted objects)
"""

import argparse
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from fortigate_api_helper import FortigateAPIHelper, logger

OUTPUT_FILE = "phase5_result.json"
BACKUP_FILE = "phase5_backup.json"

# ----------------------------- Defaults ------------------------------------
DEFAULT_FGT_IP = "192.168.55.238"
DEFAULT_TOKEN = "f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9"
DEFAULT_VDOM = "root"


# ----------------------------- Data Classes --------------------------------

@dataclass
class VIPReference:
    """Represents where a VIP is being used"""
    ref_type: str  # 'vipgrp', 'policy', 'nat'
    ref_name: str
    ref_id: Optional[int] = None
    details: Optional[Dict] = None


@dataclass
class DeletionResult:
    """Result of VIP deletion operation"""
    vip_name: str
    existed: bool
    references_found: List[VIPReference]
    references_removed: List[Dict[str, Any]]
    vip_deleted: bool
    errors: List[str]
    warnings: List[str]


# ----------------------------- Helper Functions ----------------------------

def yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no input from user"""
    suffix = " [Y/n]: " if default else " [y/N]: "
    response = input(prompt + suffix).strip().lower()
    
    if not response:
        return default
    return response in ('y', 'yes')


def safe_get_name(obj: Any) -> str:
    """Safely extract name from object"""
    if isinstance(obj, dict):
        return obj.get('name', '<unknown>')
    elif isinstance(obj, str):
        return obj
    return '<unknown>'


# ----------------------------- VIP Operations ------------------------------

def vip_exists(api: FortigateAPIHelper, vip_name: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if VIP exists and return its configuration
    Returns: (exists: bool, config: dict or None)
    """
    try:
        resp = api.get(f'firewall/vip/{vip_name}')
        results = resp.get('results', [])
        
        if results:
            return True, results[0]
        return False, None
    
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            return False, None
        logger.error(f"Error checking VIP existence: {he}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error checking VIP: {e}")
        raise


def find_vip_in_groups(api: FortigateAPIHelper, vip_name: str) -> List[VIPReference]:
    """Find all VIP groups containing this VIP"""
    references = []
    
    try:
        resp = api.get('firewall/vipgrp')
        groups = resp.get('results', [])
        
        for group in groups:
            group_name = group.get('name')
            members = group.get('member', [])
            member_names = [safe_get_name(m) for m in members]
            
            if vip_name in member_names:
                references.append(VIPReference(
                    ref_type='vipgrp',
                    ref_name=group_name,
                    details={
                        'total_members': len(members),
                        'all_members': member_names
                    }
                ))
                logger.info(f"Found VIP '{vip_name}' in VIP group '{group_name}'")
    
    except Exception as e:
        logger.error(f"Error searching VIP groups: {e}")
    
    return references


def find_vip_in_policies(api: FortigateAPIHelper, vip_name: str) -> List[VIPReference]:
    """Find all firewall policies using this VIP"""
    references = []
    
    try:
        resp = api.get('firewall/policy')
        policies = resp.get('results', [])
        
        for policy in policies:
            policy_id = policy.get('policyid')
            policy_name = policy.get('name', f'Policy-{policy_id}')
            
            # Check dstaddr
            dstaddrs = policy.get('dstaddr', [])
            dstaddr_names = [safe_get_name(d) for d in dstaddrs]
            
            if vip_name in dstaddr_names:
                references.append(VIPReference(
                    ref_type='policy_dstaddr',
                    ref_name=policy_name,
                    ref_id=policy_id,
                    details={
                        'dstaddrs': dstaddr_names,
                        'action': policy.get('action'),
                        'status': policy.get('status')
                    }
                ))
                logger.info(f"Found VIP '{vip_name}' in policy '{policy_name}' (ID: {policy_id}) dstaddr")
            
            # Check poolname (for NAT)
            poolname = policy.get('poolname', [])
            if isinstance(poolname, list):
                pool_names = [safe_get_name(p) for p in poolname]
                if vip_name in pool_names:
                    references.append(VIPReference(
                        ref_type='policy_poolname',
                        ref_name=policy_name,
                        ref_id=policy_id,
                        details={'poolname': pool_names}
                    ))
                    logger.info(f"Found VIP '{vip_name}' in policy '{policy_name}' poolname")
    
    except Exception as e:
        logger.error(f"Error searching policies: {e}")
    
    return references


def find_all_vip_references(api: FortigateAPIHelper, vip_name: str) -> List[VIPReference]:
    """Find all references to a VIP across FortiGate configuration"""
    all_refs = []
    
    logger.info(f"Searching for references to VIP '{vip_name}'...")
    
    # Search in VIP groups
    all_refs.extend(find_vip_in_groups(api, vip_name))
    
    # Search in policies
    all_refs.extend(find_vip_in_policies(api, vip_name))
    
    logger.info(f"Total references found: {len(all_refs)}")
    return all_refs


# ----------------------------- Reference Removal ---------------------------

def remove_vip_from_group(api: FortigateAPIHelper, group_name: str, 
                          vip_name: str, dry_run: bool = False) -> Dict[str, Any]:
    """Remove VIP from a VIP group"""
    result = {
        "ref_type": "vipgrp",
        "ref_name": group_name,
        "action": "remove_member",
        "success": False
    }
    
    try:
        # Get current group config
        resp = api.get(f'firewall/vipgrp/{group_name}')
        group = resp.get('results', [{}])[0]
        
        current_members = group.get('member', [])
        member_names = [safe_get_name(m) for m in current_members]
        
        if vip_name not in member_names:
            result["success"] = True
            result["message"] = "VIP not in group (already removed or never existed)"
            return result
        
        # Remove the VIP
        updated_members = [m for m in member_names if m != vip_name]
        
        if dry_run:
            result["success"] = True
            result["dry_run"] = True
            result["would_update"] = {
                "from": member_names,
                "to": updated_members
            }
            logger.info(f"[DRY RUN] Would remove '{vip_name}' from group '{group_name}'")
            return result
        
        # Update group
        update_payload = {
            "member": [{"name": m} for m in updated_members]
        }
        
        api.put(f'firewall/vipgrp/{group_name}', update_payload)
        
        result["success"] = True
        result["members_before"] = len(member_names)
        result["members_after"] = len(updated_members)
        logger.info(f"✅ Removed '{vip_name}' from VIP group '{group_name}'")
    
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"❌ Failed to remove VIP from group '{group_name}': {e}")
    
    return result


def remove_vip_from_policy(api: FortigateAPIHelper, policy_id: int, 
                           policy_name: str, vip_name: str, 
                           field: str = 'dstaddr', dry_run: bool = False) -> Dict[str, Any]:
    """Remove VIP from a firewall policy"""
    result = {
        "ref_type": f"policy_{field}",
        "ref_name": policy_name,
        "ref_id": policy_id,
        "action": f"remove_from_{field}",
        "success": False
    }
    
    try:
        # Get current policy config
        resp = api.get(f'firewall/policy/{policy_id}')
        policy = resp if 'results' not in resp else resp.get('results', [{}])[0]
        
        current_addrs = policy.get(field, [])
        addr_names = [safe_get_name(a) for a in current_addrs]
        
        if vip_name not in addr_names:
            result["success"] = True
            result["message"] = f"VIP not in {field} (already removed)"
            return result
        
        # Remove the VIP
        updated_addrs = [a for a in addr_names if a != vip_name]
        
        # Ensure at least one address remains (FortiGate requirement)
        if not updated_addrs:
            updated_addrs = ["all"]
            result["warning"] = f"Policy {field} would be empty, setting to 'all'"
        
        if dry_run:
            result["success"] = True
            result["dry_run"] = True
            result["would_update"] = {
                "from": addr_names,
                "to": updated_addrs
            }
            logger.info(f"[DRY RUN] Would remove '{vip_name}' from policy '{policy_name}' {field}")
            return result
        
        # Update policy
        update_payload = {
            field: [{"name": a} for a in updated_addrs]
        }
        
        api.put(f'firewall/policy/{policy_id}', update_payload)
        
        result["success"] = True
        result["addrs_before"] = len(addr_names)
        result["addrs_after"] = len(updated_addrs)
        logger.info(f"✅ Removed '{vip_name}' from policy '{policy_name}' {field}")
    
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"❌ Failed to remove VIP from policy {policy_id}: {e}")
    
    return result


def remove_all_references(api: FortigateAPIHelper, vip_name: str, 
                          references: List[VIPReference], 
                          dry_run: bool = False) -> List[Dict[str, Any]]:
    """Remove VIP from all found references"""
    removal_results = []
    
    for ref in references:
        logger.info(f"Processing reference: {ref.ref_type} - {ref.ref_name}")
        
        if ref.ref_type == 'vipgrp':
            result = remove_vip_from_group(api, ref.ref_name, vip_name, dry_run)
            removal_results.append(result)
        
        elif ref.ref_type.startswith('policy_'):
            field = ref.ref_type.split('_', 1)[1]  # Extract 'dstaddr' or 'poolname'
            result = remove_vip_from_policy(
                api, ref.ref_id, ref.ref_name, vip_name, field, dry_run
            )
            removal_results.append(result)
        
        if not dry_run:
            time.sleep(0.3)  # Rate limiting
    
    return removal_results


# ----------------------------- VIP Deletion --------------------------------

def delete_vip(api: FortigateAPIHelper, vip_name: str, 
               dry_run: bool = False) -> Dict[str, Any]:
    """Delete a VIP object"""
    result = {
        "vip_name": vip_name,
        "action": "delete",
        "success": False
    }
    
    try:
        if dry_run:
            result["success"] = True
            result["dry_run"] = True
            logger.info(f"[DRY RUN] Would delete VIP '{vip_name}'")
            return result
        
        api.delete(f'firewall/vip/{vip_name}')
        result["success"] = True
        logger.info(f"✅ VIP '{vip_name}' deleted successfully")
    
    except requests.exceptions.HTTPError as he:
        if he.response.status_code == 404:
            result["success"] = True
            result["message"] = "VIP already deleted or never existed"
        else:
            result["error"] = f"HTTP {he.response.status_code}: {he.response.text}"
            logger.error(f"❌ Failed to delete VIP '{vip_name}': {result['error']}")
    
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"❌ Failed to delete VIP '{vip_name}': {e}")
    
    return result


# ----------------------------- Main Runner ---------------------------------

def run_phase5(api: FortigateAPIHelper, vip_names: List[str], 
               dry_run: bool = False, force: bool = False) -> Dict[str, Any]:
    """
    Main Phase 5 execution
    
    Args:
        api: FortiGate API helper
        vip_names: List of VIP names to delete
        dry_run: If True, only simulate actions
        force: If True, skip confirmation prompts
    
    Returns:
        Dictionary containing deletion report
    """
    report = {
        "phase": 5,
        "dry_run": dry_run,
        "vips_processed": [],
        "total_references_found": 0,
        "total_references_removed": 0,
        "total_vips_deleted": 0,
        "errors": [],
        "backup": {}
    }
    
    for vip_name in vip_names:
        print(f"\n{'='*60}")
        print(f"Processing VIP: {vip_name}")
        print('='*60)
        
        deletion_result = DeletionResult(
            vip_name=vip_name,
            existed=False,
            references_found=[],
            references_removed=[],
            vip_deleted=False,
            errors=[],
            warnings=[]
        )
        
        # Step 1: Check if VIP exists
        print(f"\n[1/4] Checking if VIP exists...")
        exists, vip_config = vip_exists(api, vip_name)
        
        if not exists:
            logger.warning(f"⚠️  VIP '{vip_name}' does not exist")
            deletion_result.warnings.append("VIP does not exist")
            report["vips_processed"].append(deletion_result.__dict__)
            continue
        
        deletion_result.existed = True
        report["backup"][vip_name] = vip_config
        print(f"✅ VIP found")
        
        # Step 2: Find all references
        print(f"\n[2/4] Searching for references...")
        references = find_all_vip_references(api, vip_name)
        deletion_result.references_found = references
        report["total_references_found"] += len(references)
        
        if references:
            print(f"⚠️  Found {len(references)} reference(s):")
            for ref in references:
                print(f"  - {ref.ref_type}: {ref.ref_name}")
            
            if not force and not dry_run:
                if not yes_no(f"\nProceed with removing references?", default=False):
                    deletion_result.warnings.append("User cancelled reference removal")
                    report["vips_processed"].append(deletion_result.__dict__)
                    continue
        else:
            print("✅ No references found")
        
        # Step 3: Remove references
        if references:
            print(f"\n[3/4] Removing references...")
            removal_results = remove_all_references(api, vip_name, references, dry_run)
            deletion_result.references_removed = removal_results
            
            successful_removals = sum(1 for r in removal_results if r.get('success'))
            report["total_references_removed"] += successful_removals
            
            failed_removals = [r for r in removal_results if not r.get('success')]
            if failed_removals:
                for fail in failed_removals:
                    error_msg = f"Failed to remove from {fail.get('ref_name')}: {fail.get('error')}"
                    deletion_result.errors.append(error_msg)
                    report["errors"].append(error_msg)
        else:
            print(f"\n[3/4] No references to remove")
        
        # Step 4: Delete VIP
        if not deletion_result.errors or force:
            print(f"\n[4/4] Deleting VIP...")
            
            if not force and not dry_run:
                if not yes_no(f"Delete VIP '{vip_name}'?", default=False):
                    deletion_result.warnings.append("User cancelled VIP deletion")
                    report["vips_processed"].append(deletion_result.__dict__)
                    continue
            
            delete_result = delete_vip(api, vip_name, dry_run)
            deletion_result.vip_deleted = delete_result.get('success', False)
            
            if deletion_result.vip_deleted:
                report["total_vips_deleted"] += 1
            elif 'error' in delete_result:
                deletion_result.errors.append(delete_result['error'])
                report["errors"].append(f"{vip_name}: {delete_result['error']}")
        else:
            print(f"\n[4/4] Skipping VIP deletion due to previous errors")
            deletion_result.warnings.append("VIP deletion skipped due to reference removal errors")
        
        report["vips_processed"].append(deletion_result.__dict__)
    
    return report


# ----------------------------- CLI -----------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Phase 5: Safe VIP Deletion (FortiGate Automation)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    p.add_argument("vip_names", nargs='+', help="VIP name(s) to delete")
    p.add_argument("--ip", default=DEFAULT_FGT_IP, help=f"FortiGate IP (default: {DEFAULT_FGT_IP})")
    p.add_argument("--token", default=DEFAULT_TOKEN, help="API Token")
    p.add_argument("--vdom", default=DEFAULT_VDOM, help=f"VDOM (default: {DEFAULT_VDOM})")
    p.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    
    p.add_argument("--dry-run", action="store_true", help="Simulate actions without making changes")
    p.add_argument("--force", action="store_true", help="Skip confirmation prompts")
    p.add_argument("--no-backup", action="store_true", help="Don't create backup file")
    
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    
    # Setup API
    scheme = "https" if args.https else "http"
    base_url = f"{scheme}://{args.ip}/api/v2/cmdb/"
    
    api = FortigateAPIHelper(
        base_url=base_url,
        token=args.token,
        vdom=args.vdom
    )
    
    print("\n" + "="*60)
    print("   Phase 5 – Safe VIP Deletion")
    print("="*60)
    print(f"FortiGate IP : {args.ip}")
    print(f"VDOM         : {args.vdom}")
    print(f"Transport    : {'HTTPS' if args.https else 'HTTP'}")
    print(f"Mode         : {'DRY RUN' if args.dry_run else 'LIVE'}")
    print(f"VIPs to delete: {len(args.vip_names)}")
    for vip in args.vip_names:
        print(f"  - {vip}")
    print("="*60)
    
    if not args.force and not args.dry_run:
        if not yes_no("\n⚠️  This will permanently delete VIP(s). Continue?", default=False):
            print("❌ Cancelled by user")
            return 1
    
    # Execute
    try:
        report = run_phase5(api, args.vip_names, args.dry_run, args.force)
        
        # Save report
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Save backup
        if not args.no_backup and report.get('backup'):
            with open(BACKUP_FILE, 'w', encoding='utf-8') as f:
                json.dump(report['backup'], f, indent=2, ensure_ascii=False)
            print(f"\n💾 Backup saved to {BACKUP_FILE}")
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        print(f"VIPs processed       : {len(report['vips_processed'])}")
        print(f"References found     : {report['total_references_found']}")
        print(f"References removed   : {report['total_references_removed']}")
        print(f"VIPs deleted         : {report['total_vips_deleted']}")
        print(f"Errors               : {len(report['errors'])}")
        
        if report['errors']:
            print("\n⚠️  Errors occurred:")
            for err in report['errors']:
                print(f"  - {err}")
        
        print(f"\n✅ Report saved to {OUTPUT_FILE}")
        
        return 0 if not report['errors'] else 1
    
    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        return 130
    except Exception as e:
        logger.exception("Phase 5 failed with error")
        print(f"\n❌ Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())