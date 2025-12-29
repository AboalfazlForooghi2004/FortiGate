#!/usr/bin/env python3
# phase4.py (Fixed Version - Complete Rewrite)

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
    """
    Parse comma-separated IP:PORT pairs
    Example: "10.10.10.10:80,10.10.10.11:443"
    """
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


def get_interfaces(api: FortigateAPIHelper) -> List[str]:
    """Get list of available interfaces"""
    try:
        r = api.get('system/interface')
        return [i.get('name') for i in r.get('results', []) if i.get('name')]
    except Exception as e:
        logger.warning(f"Cannot enumerate interfaces: {e}")
        return []


def vip_exists(api: FortigateAPIHelper, name: str) -> bool:
    """Check if VIP already exists"""
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
    """
    Check if there's an overlapping VIP (same extip + port)
    Returns the name of overlapping VIP or None
    """
    try:
        all_vips = api.get('firewall/vip').get('results', [])
        
        for vip in all_vips:
            if vip.get('extip') == extip:
                # Check port overlap
                existing_port = vip.get('extport', '')
                if existing_port:
                    # Parse port or port range
                    if '-' in existing_port:
                        start, end = existing_port.split('-')
                        if int(start) <= extport <= int(end):
                            return vip.get('name')
                    elif int(existing_port) == extport:
                        return vip.get('name')
        
        return None
    except Exception as e:
        logger.warning(f"Could not check VIP overlap: {e}")
        return None


def create_vip_fixed(api: FortigateAPIHelper, name: str, extip: str, mappedip: str,
                     port: int = None, extintf: str = "any", protocol: str = "tcp"):
    """
    ✅ FIXED: Create VIP with correct FortiGate API format
    
    Key Fix: mappedip must be in range format: "IP-IP" inside a dict
    """
    if not validate_ip(mappedip):
        return {"ok": False, "error": f"Invalid mappedip: {mappedip}"}

    # ✅ CRITICAL FIX: mappedip format must be [{"range": "IP-IP"}]
    mapped_range = f"{mappedip}-{mappedip}"
    
    if port is not None:
        # Port forwarding VIP
        payload = {
            "name": name,
            "type": "static-nat",
            "extintf": extintf,
            "extip": extip,
            "mappedip": [{"range": mapped_range}],  # ✅ Correct format
            "portforward": "enable",
            "protocol": protocol,
            "extport": f"{port}-{port}",
            "mappedport": f"{port}-{port}"
        }
    else:
        # Simple static NAT
        payload = {
            "name": name,
            "type": "static-nat",
            "extintf": extintf,
            "extip": extip,
            "mappedip": [{"range": mapped_range}]  # ✅ Correct format
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


def create_vip_group(api: FortigateAPIHelper, group_name: str, members: List[str]):
    """Create VIP group"""
    payload = {
        "name": group_name,
        "member": [{"name": m} for m in members]
    }
    
    try:
        resp = api.post('firewall/vipgrp', payload)
        logger.info(f"✅ VIP group '{group_name}' created")
        return {"ok": True, "resp": resp}
    
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except:
            body = resp.text if resp else str(he)
        
        logger.error(f"❌ VIP group creation failed - HTTP {resp.status_code}: {body}")
        return {"ok": False, "status": resp.status_code, "error": body}
    
    except Exception as e:
        logger.exception("❌ VIP group creation failed")
        return {"ok": False, "error": str(e)}


def create_policy(api: FortigateAPIHelper, name: str, srcintf: str, dstintf: str,
                 dstaddr: str, service: str, action: str):
    """Create firewall policy"""
    payload = {
        "name": name,
        "srcintf": [{"name": srcintf}],
        "dstintf": [{"name": dstintf}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": dstaddr}],
        "service": [{"name": service}],
        "action": action,
        "schedule": "always",
        "status": "enable",
        "nat": "disable"
    }
    
    try:
        resp = api.post('firewall/policy', payload)
        logger.info(f"✅ Policy '{name}' created")
        return {"ok": True, "resp": resp}
    
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except:
            body = resp.text if resp else str(he)
        
        logger.error(f"❌ Policy creation failed - HTTP {resp.status_code}: {body}")
        return {"ok": False, "status": resp.status_code, "error": body}
    
    except Exception as e:
        logger.exception("❌ Policy creation failed")
        return {"ok": False, "error": str(e)}


def yes_no(prompt: str) -> bool:
    """Get yes/no input from user"""
    return input(prompt).strip().lower() in ('y', 'yes')


def main():
    print("\n" + "="*60)
    print("   Phase 4 – Automated VIP Publish (FIXED VERSION)")
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

    # Check available interfaces
    interfaces = get_interfaces(api)
    if interfaces:
        print(f"\nℹ️  Available interfaces: {', '.join(interfaces)}")
    
    ext_intf = input("External interface [wan1]: ").strip() or "wan1"
    if interfaces and ext_intf not in interfaces:
        print(f"⚠️  Warning: '{ext_intf}' not found in available interfaces")
        if not yes_no("Continue anyway? (y/n): "):
            return 1

    vipgrp_name = input("\nVIP Group name [AUTO_VIP_GRP]: ").strip() or "AUTO_VIP_GRP"
    policy_name = input("Policy name [AUTO_PUBLISH_POLICY]: ").strip() or "AUTO_PUBLISH_POLICY"
    src_intf = input("Source interface [lan]: ").strip() or "lan"
    dst_intf = input("Destination interface [wan1]: ").strip() or "wan1"
    service = input("Service [ALL]: ").strip() or "ALL"
    action = input("Action [accept]: ").strip() or "accept"

    dry_run = yes_no("\nDry run mode? (y/n): ")

    # ===== PROCESSING =====
    results = {
        "vips": [],
        "vip_group": None,
        "policy": None,
        "errors": [],
        "warnings": []
    }
    vip_names = []

    print("\n" + "="*60)
    print("CREATING VIPs")
    print("="*60)

    for mapped_ip, port in ips_ports:
        vip_name = f"VIP_{mapped_ip.replace('.', '_')}_{port}"
        print(f"\n[{len(vip_names)+1}/{len(ips_ports)}] Processing: {vip_name}")

        # Check if exists
        try:
            if vip_exists(api, vip_name):
                logger.info(f"ℹ️  VIP already exists: {vip_name}")
                vip_names.append(vip_name)
                results["vips"].append({"name": vip_name, "status": "exists"})
                continue
        except Exception as e:
            results["errors"].append({
                "vip": vip_name,
                "error": f"existence_check_failed: {e}"
            })
            continue

        # Check for overlaps
        overlap = check_vip_overlap(api, ext_ip, port)
        if overlap:
            msg = f"⚠️  VIP would overlap with existing VIP: {overlap}"
            logger.warning(msg)
            results["warnings"].append({"vip": vip_name, "warning": msg})
            # Skip this VIP
            continue

        logger.info(f"Creating VIP: {vip_name} → {ext_ip}:{port} => {mapped_ip}:{port}")

        if dry_run:
            vip_names.append(vip_name)
            results["vips"].append({"name": vip_name, "status": "dry-run"})
            print("  [DRY RUN] Would create VIP")
            continue

        # ✅ Create VIP with fixed function
        res = create_vip_fixed(
            api, vip_name, ext_ip, mapped_ip,
            port=port, extintf=ext_intf
        )

        if res.get("ok"):
            vip_names.append(vip_name)
            results["vips"].append({
                "name": vip_name,
                "status": "created",
                "response": res.get("resp")
            })
            print(f"  ✅ Created successfully")
        else:
            results["errors"].append({"vip": vip_name, "result": res})
            print(f"  ❌ Failed: {res.get('error')}")

        time.sleep(0.3)  # Rate limiting

    # ===== VIP GROUP =====
    if not vip_names:
        logger.error("❌ No VIPs created. Aborting.")
        results["message"] = "no_vips_created"
    else:
        print("\n" + "="*60)
        print("CREATING VIP GROUP")
        print("="*60)
        
        if dry_run:
            results["vip_group"] = {"name": vipgrp_name, "status": "dry-run"}
            print(f"[DRY RUN] Would create VIP group: {vipgrp_name}")
        else:
            grp_res = create_vip_group(api, vipgrp_name, vip_names)
            if grp_res.get("ok"):
                results["vip_group"] = {
                    "name": vipgrp_name,
                    "status": "created",
                    "members": vip_names,
                    "response": grp_res["resp"]
                }
            else:
                results["errors"].append({"vip_group": grp_res})
                print(f"❌ VIP Group creation failed")

        # ===== FIREWALL POLICY =====
        print("\n" + "="*60)
        print("CREATING FIREWALL POLICY")
        print("="*60)
        
        if dry_run:
            results["policy"] = {"name": policy_name, "status": "dry-run"}
            print(f"[DRY RUN] Would create policy: {policy_name}")
        else:
            pol_res = create_policy(
                api, policy_name, src_intf, dst_intf,
                vipgrp_name, service, action
            )
            if pol_res.get("ok"):
                results["policy"] = {
                    "name": policy_name,
                    "status": "created",
                    "response": pol_res["resp"]
                }
            else:
                results["errors"].append({"policy": pol_res})

    # ===== SAVE RESULTS =====
    with open("phase4_result.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # ===== SUMMARY =====
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"VIPs processed : {len(vip_names)}/{len(ips_ports)}")
    print(f"VIP Group      : {results.get('vip_group', {}).get('status', 'N/A')}")
    print(f"Policy         : {results.get('policy', {}).get('status', 'N/A')}")
    print(f"Errors         : {len(results['errors'])}")
    print(f"Warnings       : {len(results['warnings'])}")
    print(f"\n✅ Results saved to phase4_result.json\n")

    return 0 if not results['errors'] else 1


if __name__ == '__main__':
    exit(main())