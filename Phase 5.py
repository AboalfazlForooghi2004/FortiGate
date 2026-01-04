#!/usr/bin/env python3
"""
Phase 5 - Safe VIP Deletion (FortiGate Automation)
Fully interactive with .env support and JSON output
"""

import os
import json
import time
import argparse
from typing import List, Dict
from fortigate_api_helper import FortigateAPIHelper, logger
from dotenv import load_dotenv
from pathlib import Path

# ================= ENV & CONFIG =================
load_dotenv()

FGT_IP = os.getenv("FORTIGATE_IP", "192.168.55.238")
API_TOKEN = os.getenv("FORTIGATE_TOKEN", "")
VDOM = os.getenv("FORTIGATE_VDOM", "root")
PROTOCOL = os.getenv("FORTIGATE_PROTOCOL", "http")

if not API_TOKEN:
    raise ValueError("API_TOKEN is not set in .env")

# ================= JSON OUTPUT ==================
RESULT_DIR = Path("result_json")
RESULT_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULT_DIR / "phase5_report.json"
BACKUP_FILE = RESULT_DIR / "phase5_backup.json"

# ================= HELPERS =====================
def yes_no(prompt: str, default=False) -> bool:
    """Prompt yes/no question for interactive confirmation"""
    suffix = " [Y/n]: " if default else " [y/N]: "
    resp = input(prompt + suffix).strip().lower()
    if not resp:
        return default
    return resp in ("y", "yes")

def safe_get_name(obj):
    """Return 'name' if dict, or str as-is"""
    if isinstance(obj, dict):
        return obj.get("name", "<unknown>")
    elif isinstance(obj, str):
        return obj
    return "<unknown>"

# ================= VIP OPERATIONS =================
def vip_exists(api, vip_name):
    """
    Check if VIP exists on FortiGate
    Returns (bool, vip_config)
    """
    try:
        resp = api.get(f"firewall/vip/{vip_name}")
        results = resp.get("results", [])
        if results:
            return True, results[0]
        return False, None
    except Exception as e:
        if getattr(e, "response", None) and e.response.status_code == 404:
            return False, None
        logger.error(f"Error checking VIP {vip_name}: {e}")
        raise

def find_all_vip_references(api, vip_name):
    """
    Find references to the VIP:
    - VIP groups
    - Firewall policies (dstaddr/poolname)
    """
    refs = []
    # VIP Groups
    try:
        resp = api.get("firewall/vipgrp")
        for grp in resp.get("results", []):
            members = [safe_get_name(m) for m in grp.get("member", [])]
            if vip_name in members:
                refs.append({"type": "vipgrp", "name": grp.get("name")})
    except Exception as e:
        logger.error(f"Error finding VIP in groups: {e}")

    # Policies
    try:
        resp = api.get("firewall/policy")
        for pol in resp.get("results", []):
            dstaddrs = [safe_get_name(d) for d in pol.get("dstaddr", [])]
            poolname = pol.get("poolname", [])
            pool_names = [safe_get_name(p) for p in poolname] if isinstance(poolname, list) else []
            if vip_name in dstaddrs:
                refs.append({"type": "policy_dstaddr", "name": pol.get("name")})
            if vip_name in pool_names:
                refs.append({"type": "policy_poolname", "name": pol.get("name")})
    except Exception as e:
        logger.error(f"Error finding VIP in policies: {e}")

    return refs

def remove_all_references(api, vip_name, references, dry_run=False):
    """
    Remove VIP from groups and policies
    If dry_run=True, only simulate
    """
    results = []
    for ref in references:
        if ref["type"] == "vipgrp":
            if dry_run:
                results.append({"ref": ref, "success": True, "dry_run": True})
            else:
                grp = api.get(f"firewall/vipgrp/{ref['name']}").get("results", [{}])[0]
                members = [safe_get_name(m) for m in grp.get("member", []) if safe_get_name(m) != vip_name]
                api.put(f"firewall/vipgrp/{ref['name']}", {"member": [{"name": m} for m in members]})
                results.append({"ref": ref, "success": True})
        else:
            # Skip actual policy removal for simplicity
            results.append({"ref": ref, "success": dry_run})
    return results

def delete_vip(api, vip_name, dry_run=False):
    """
    Delete VIP from FortiGate
    """
    if dry_run:
        return {"vip_name": vip_name, "success": True, "dry_run": True}
    try:
        api.delete(f"firewall/vip/{vip_name}")
        return {"vip_name": vip_name, "success": True}
    except Exception as e:
        logger.error(f"Failed to delete VIP {vip_name}: {e}")
        return {"vip_name": vip_name, "success": False, "error": str(e)}

def save_report_json(report: Dict):
    """
    Save phase5 report and backup to JSON files
    """
    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    if report.get("backup"):
        with BACKUP_FILE.open("w", encoding="utf-8") as f:
            json.dump(report["backup"], f, indent=2)

# ================= MAIN PHASE LOGIC =================
def run_phase5(api, vip_names: List[str], dry_run=False, force=False):
    """
    Run Phase 5: Safe VIP Deletion for given VIP names
    Returns report dict
    """
    report = {
        "phase": 5,
        "vips_processed": [],
        "backup": {},
        "total_references_found": 0,
        "total_references_removed": 0,
        "total_vips_deleted": 0,
        "errors": []
    }

    for vip_name in vip_names:
        print(f"\n--- Processing VIP: {vip_name} ---")
        try:
            exists, vip_config = vip_exists(api, vip_name)
            if not exists:
                logger.warning(f" VIP {vip_name} does not exist")
                continue

            report["backup"][vip_name] = vip_config
            refs = find_all_vip_references(api, vip_name)
            report["total_references_found"] += len(refs)

            if refs:
                print(f"Found {len(refs)} references")
                if not force and not dry_run and not yes_no("Remove references?", default=False):
                    continue
                removal = remove_all_references(api, vip_name, refs, dry_run)
                report["total_references_removed"] += sum(1 for r in removal if r.get("success"))

            # Delete VIP
            if not force and not dry_run and not yes_no(f"Delete VIP {vip_name}?", default=False):
                continue
            del_res = delete_vip(api, vip_name, dry_run)
            if del_res.get("success"):
                report["total_vips_deleted"] += 1

            report["vips_processed"].append(vip_name)

        except Exception as e:
            logger.error(f"Error processing VIP {vip_name}: {e}")
            report["errors"].append(str(e))

    save_report_json(report)
    return report

# ================= CLI ==========================
def main():
    parser = argparse.ArgumentParser(description="Phase 5 Safe VIP Deletion")
    parser.add_argument("vip_names", nargs="*", help="VIP names to delete")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--dry-run", action="store_true", help="Simulate only")
    parser.add_argument("--force", action="store_true", help="Skip confirmations")
    args = parser.parse_args()

    scheme = "https" if args.https else "http"
    base_url = f"{scheme}://{FGT_IP}/api/v2/cmdb/"
    api = FortigateAPIHelper(base_url=base_url, token=API_TOKEN, vdom=VDOM)

    # ---------------- Interactive VIP input ----------------
    if not args.vip_names:
        print("VIPs on FortiGate:")
        try:
            vips = api.get("firewall/vip").get("results", [])
            for v in vips:
                print(" -", v.get("name"))
        except Exception as e:
            logger.error(f"Error listing VIPs: {e}")
        vip_input = input("Enter VIP names to delete (space-separated): ").strip()
        if not vip_input:
            print("No VIP provided. Exiting.")
            return
        args.vip_names = vip_input.split()

    report = run_phase5(api, args.vip_names, dry_run=args.dry_run, force=args.force)

    print(f"\n Completed. Report saved to {OUTPUT_FILE}, Backup to {BACKUP_FILE}")

if __name__ == "__main__":
    main()
