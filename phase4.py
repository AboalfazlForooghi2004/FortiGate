#!/usr/bin/env python3
# phase4.py - Fixed V2 (Compatible with new FortiOS format)

import json
import time
import ipaddress
import requests
from typing import List, Tuple
from fortigate_api_helper import FortigateAPIHelper, logger

# ======== CONFIG ========
FORTIGATE_IP = '192.168.55.238'
TOKEN = 'f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9'
BASE_URL = f'http://{FORTIGATE_IP}/api/v2/cmdb/'
VDOM = "root"
# ========================


def validate_ip(ip: str) -> bool:
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_ip_ports(raw: str) -> List[Tuple[str, int]]:
    """Parse comma-separated IP:PORT pairs"""
    pairs = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        if ':' not in item:
            raise ValueError(f"Invalid pair (expected ip:port): {item}")
        
        ip, port = item.split(':', 1)
        ip = ip.strip()
        port = port.strip()
        
        if not validate_ip(ip):
            raise ValueError(f"Invalid IP: {ip}")
        
        try:
            p = int(port)
            if not (1 <= p <= 65535):
                raise ValueError
        except Exception:
            raise ValueError(f"Invalid port: {port}")
        
        pairs.append((ip, p))
    
    return pairs


def vip_exists(api: FortigateAPIHelper, name: str) -> bool:
    """Check if VIP exists"""
    try:
        api.get(f'firewall/vip/{name}')
        return True
    except requests.exceptions.HTTPError as he:
        resp = getattr(he, "response", None)
        if resp is not None and resp.status_code == 404:
            return False
        raise
    except Exception:
        return False


def check_vip_overlap(api: FortigateAPIHelper, extip: str, extport: int) -> str | None:
    """Check if there's an overlapping VIP"""
    try:
        all_vips = api.get('firewall/vip').get('results', [])
        
        for vip in all_vips:
            if vip.get('extip') == extip:
                existing_port = vip.get('extport', '')
                if existing_port:
                    # Handle both string and int formats
                    if isinstance(existing_port, str):
                        if '-' in existing_port:
                            start, end = existing_port.split('-')
                            if int(start) <= extport <= int(end):
                                return vip.get('name')
                        elif int(existing_port) == extport:
                            return vip.get('name')
                    elif isinstance(existing_port, int) and existing_port == extport:
                        return vip.get('name')
        
        return None
    except Exception as e:
        logger.warning(f"Could not check VIP overlap: {e}")
        return None


def create_vip_new_format(api: FortigateAPIHelper, name: str, extip: str, mappedip: str,
                          port: int = None, extintf: str = "any", protocol: str = "tcp"):
    """
    ✅ NEW FORMAT: Compatible with FortiOS 7.4+
    Key changes:
    - mappedip: [{"range": "IP"}] not "IP-IP"
    - extport/mappedport: integer not string
    - No explicit type field
    """
    if not validate_ip(mappedip):
        return {"ok": False, "error": f"Invalid mappedip: {mappedip}"}

    if port is not None:
        # Port forwarding VIP
        payload = {
            "name": name,
            "extintf": extintf,
            "extip": extip,
            "mappedip": [{"range": mappedip}],  # ✅ Simple format
            "portforward": "enable",
            "protocol": protocol,
            "extport": port,        # ✅ Integer not string
            "mappedport": port,     # ✅ Integer not string
            "comment": f"Auto-created VIP for {mappedip}:{port}"
        }
    else:
        # Simple static NAT
        payload = {
            "name": name,
            "extintf": extintf,
            "extip": extip,
            "mappedip": [{"range": mappedip}],  # ✅ Simple format
            "comment": f"Auto-created VIP for {mappedip}"
        }

    try:
        resp = api.post('firewall/vip', payload)
        logger.info(f"✅ VIP '{name}' created successfully")
        return {"ok": True, "resp": resp, "payload": payload}
    
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
            error_msg = body.get('cli_error', body)
        except:
            error_msg = resp.text if resp else str(he)
        
        logger.error(f"❌ VIP creation failed - HTTP {resp.status_code}: {error_msg}")
        return {
            "ok": False,
            "status": resp.status_code,
            "error": error_msg,
            "payload": payload
        }
    
    except Exception as e:
        logger.exception("❌ VIP creation failed")
        return {"ok": False, "error": str(e), "payload": payload}


def create_vip_group_twostep(api: FortigateAPIHelper, group_name: str, 
                              extintf: str, members: List[str]):
    """
    ✅ TWO-STEP VIP Group creation (like Phase4.py)
    Step 1: Create empty group
    Step 2: PUT members
    """
    # Step 1: Create empty group
    try:
        exists = False
        try:
            api.get(f'firewall/vipgrp/{group_name}')
            exists = True
            logger.info(f"ℹ️  VIP group '{group_name}' already exists")
        except requests.exceptions.HTTPError as he:
            if he.response.status_code != 404:
                raise
        
        if not exists:
            empty_payload = {
                "name": group_name,
                "interface": extintf,
                "member": [],
                "comment": "Auto-created VIP group"
            }
            resp = api.post('firewall/vipgrp', empty_payload)
            logger.info(f"✅ Empty VIP group '{group_name}' created")
            time.sleep(0.5)  # Let FortiGate process
    
    except Exception as e:
        logger.error(f"❌ Failed to create empty VIP group: {e}")
        return {"ok": False, "error": str(e), "step": "create_empty"}

    # Step 2: PUT members
    try:
        update_payload = {
            "interface": extintf,
            "member": [{"name": m} for m in members],
            "comment": f"VIP group with {len(members)} members"
        }
        resp = api.put(f'firewall/vipgrp/{group_name}', update_payload)
        logger.info(f"✅ VIP group '{group_name}' updated with {len(members)} members")
        return {"ok": True, "resp": resp, "members": members}
    
    except Exception as e:
        logger.exception("❌ Failed to update VIP group members")
        return {"ok": False, "error": str(e), "step": "put_members"}


def create_policy_twostep(api: FortigateAPIHelper, name: str, srcintf: str, 
                          dstintf: str, vipgrp_name: str, service: str = "ALL"):
    """
    ✅ TWO-STEP Policy creation (like Phase4.py)
    Step 1: Create with dstaddr="all"
    Step 2: Update to actual VIP Group
    """
    # Check if exists
    try:
        all_policies = api.get('firewall/policy').get('results', [])
        existing = next((p for p in all_policies if p.get('name') == name), None)
        
        if existing:
            policy_id = existing.get('policyid')
            logger.info(f"ℹ️  Policy '{name}' already exists (ID: {policy_id})")
        else:
            # Step 1: Create with safe dstaddr
            create_payload = {
                "name": name,
                "srcintf": [{"name": srcintf}],
                "dstintf": [{"name": dstintf}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],  # ✅ Safe initial value
                "service": [{"name": service}],
                "action": "accept",
                "schedule": "always",
                "status": "enable",
                "nat": "disable",
                "logtraffic": "all",
                "comments": "Auto-created policy for VIP group"
            }
            
            resp = api.post('firewall/policy', create_payload)
            logger.info(f"✅ Policy '{name}' created")
            
            # Find the new policy ID
            time.sleep(0.5)
            all_policies = api.get('firewall/policy').get('results', [])
            existing = next((p for p in all_policies if p.get('name') == name), None)
            
            if not existing:
                return {"ok": False, "error": "Policy created but not found"}
            
            policy_id = existing.get('policyid')
    
    except Exception as e:
        logger.exception("❌ Failed to create policy")
        return {"ok": False, "error": str(e), "step": "create"}

    # Step 2: Update to VIP Group
    try:
        update_payload = {
            "dstaddr": [{"name": vipgrp_name}],
            "comments": f"Publishing VIP group: {vipgrp_name}"
        }
        
        resp = api.put(f'firewall/policy/{policy_id}', update_payload)
        logger.info(f"✅ Policy '{name}' updated with VIP group '{vipgrp_name}'")
        return {"ok": True, "resp": resp, "policyid": policy_id}
    
    except Exception as e:
        logger.exception("❌ Failed to update policy")
        return {"ok": False, "error": str(e), "step": "update", "policyid": policy_id}


def yes_no(prompt: str) -> bool:
    """Get yes/no input"""
    return input(prompt).strip().lower() in ('y', 'yes')


def main():
    print("\n" + "="*60)
    print("   Phase 4 – VIP Publish (New Compatible Format)")
    print("="*60 + "\n")

    api = FortigateAPIHelper(BASE_URL, TOKEN, vdom=VDOM)

    # ===== INPUT =====
    raw_pairs = input("Enter IP:PORT pairs (comma separated)\n[e.g. 10.10.10.10:80,10.10.10.11:443]:\n> ").strip()
    
    try:
        ips_ports = parse_ip_ports(raw_pairs)
        print(f"✅ Parsed {len(ips_ports)} IP:PORT pairs")
    except Exception as e:
        print(f"❌ Invalid input: {e}")
        return 1

    ext_ip = input("\nExternal IP (extip): ").strip()
    if not validate_ip(ext_ip):
        print("❌ Invalid External IP")
        return 1

    ext_intf = input("External interface [port1]: ").strip() or "port1"
    vipgrp_name = input("VIP Group name [AUTO_VIP_GRP]: ").strip() or "AUTO_VIP_GRP"
    policy_name = input("Policy name [AUTO_PUBLISH_POLICY]: ").strip() or "AUTO_PUBLISH_POLICY"
    src_intf = input("Source interface [port1]: ").strip() or "port1"
    dst_intf = input("Destination interface [port4]: ").strip() or "port4"
    service = input("Service [ALL]: ").strip() or "ALL"

    dry_run = yes_no("\nDry run mode? (y/n): ")

    # ===== PROCESSING =====
    results = {
        "vips": [],
        "vip_group": None,
        "policy": None,
        "errors": []
    }
    vip_names = []

    print("\n" + "="*60)
    print("STEP 1: CREATING VIPs (New Format)")
    print("="*60)

    for mapped_ip, port in ips_ports:
        vip_name = f"VIP_{mapped_ip.replace('.', '_')}_{port}"
        print(f"\n[{len(vip_names)+1}/{len(ips_ports)}] Processing: {vip_name}")

        # Check existence
        try:
            if vip_exists(api, vip_name):
                logger.info(f"ℹ️  VIP already exists: {vip_name}")
                vip_names.append(vip_name)
                results["vips"].append({"name": vip_name, "status": "exists"})
                continue
        except Exception as e:
            results["errors"].append({"vip": vip_name, "error": f"check_failed: {e}"})
            continue

        # Check overlap
        overlap = check_vip_overlap(api, ext_ip, port)
        if overlap:
            logger.warning(f"⚠️  Overlap with: {overlap}")
            continue

        if dry_run:
            vip_names.append(vip_name)
            results["vips"].append({"name": vip_name, "status": "dry-run"})
            print("  [DRY RUN] Would create VIP")
            continue

        # ✅ Create with new format
        res = create_vip_new_format(api, vip_name, ext_ip, mapped_ip, 
                                    port=port, extintf=ext_intf)

        if res.get("ok"):
            vip_names.append(vip_name)
            results["vips"].append({"name": vip_name, "status": "created"})
            print(f"  ✅ Created")
        else:
            results["errors"].append({"vip": vip_name, "result": res})
            print(f"  ❌ Failed: {res.get('error')}")

        time.sleep(0.5)

    if not vip_names:
        print("\n❌ No VIPs created. Aborting.")
        return 1

    # ===== VIP GROUP (Two-Step) =====
    print("\n" + "="*60)
    print("STEP 2: CREATING VIP GROUP (Two-Step Method)")
    print("="*60)
    
    if dry_run:
        results["vip_group"] = {"name": vipgrp_name, "status": "dry-run"}
        print(f"[DRY RUN] Would create VIP group")
    else:
        grp_res = create_vip_group_twostep(api, vipgrp_name, ext_intf, vip_names)
        results["vip_group"] = grp_res

    # ===== POLICY (Two-Step) =====
    print("\n" + "="*60)
    print("STEP 3: CREATING POLICY (Two-Step Method)")
    print("="*60)
    
    if dry_run:
        results["policy"] = {"name": policy_name, "status": "dry-run"}
        print(f"[DRY RUN] Would create policy")
    else:
        pol_res = create_policy_twostep(api, policy_name, src_intf, 
                                        dst_intf, vipgrp_name, service)
        results["policy"] = pol_res

    # ===== SAVE =====
    with open("phase4_result.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # ===== SUMMARY =====
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"VIPs created  : {len(vip_names)}/{len(ips_ports)}")
    print(f"VIP Group     : {results.get('vip_group', {}).get('ok', 'N/A')}")
    print(f"Policy        : {results.get('policy', {}).get('ok', 'N/A')}")
    print(f"Errors        : {len(results['errors'])}")
    print(f"\n✅ Results saved to phase4_result.json\n")

    return 0 if not results['errors'] else 1


if __name__ == '__main__':
    exit(main())