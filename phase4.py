#!/usr/bin/env python3
# phase4.py (final + mappedip fallback)

import json
import time
import ipaddress
import requests
from fortigate_api_helper import FortigateAPIHelper, logger

# ======== CONFIG ========
FORTIGATE_IP = '192.168.55.238'
TOKEN = 'f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9'
BASE_URL = f'http://{FORTIGATE_IP}/api/v2/cmdb/'
VDOM = "root"
# ========================


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_ip_ports(raw: str):
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


def get_interfaces(api: FortigateAPIHelper):
    try:
        r = api.get('system/interface')
        return [i.get('name') for i in r.get('results', []) if i.get('name')]
    except Exception as e:
        logger.warning("Cannot enumerate interfaces: %s", e)
        return []


def vip_exists(api: FortigateAPIHelper, name: str) -> bool:
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


def _try_post(api, payload):
    """
    helper: try api.post and normalize the result dict:
    returns {"ok":True,"resp":<api_response>} or {"ok":False,"status":..., "body":...}
    """
    try:
        resp = api.post('firewall/vip', payload)
        return {"ok": True, "resp": resp}
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except Exception:
            body = resp.text if resp is not None else str(he)
        logger.error("VIP creation HTTPError: %s %s", getattr(resp, "status_code", "?"), body)
        return {"ok": False, "status": getattr(resp, "status_code", None), "body": body}
    except Exception as e:
        logger.exception("VIP creation failed (other)")
        return {"ok": False, "error": str(e)}


def create_vip_with_fallback(api: FortigateAPIHelper, name: str, extip: str, mappedip: str,
                             port: int = None, extintf: str = "any", protocol: str = "tcp"):
    """
    Try several payload formats until one is accepted.
    Returns a dict with keys:
      - ok: bool
      - resp: (api response) if ok
      - tried: list of payloads attempted (for debugging)
      - errors: list of responses/errors for each attempt
    """
    tried = []
    errors = []

    # base validations
    if not validate_ip(mappedip):
        return {"ok": False, "error": f"invalid mappedip {mappedip}", "tried": [], "errors": []}

    # Candidate payloads (order matters)
    candidates = []

    # 1) portforward (type: portforward) with mappedip as string — common REST format
    if port is not None:
        candidates.append({
            "name": name,
            "type": "portforward",
            "extintf": extintf,
            "extip": extip,
            "mappedip": mappedip,
            "extport": str(port),
            "mappedport": str(port),
            "protocol": protocol,
            "arp-reply": "enable"
        })
    else:
        # static-nat with mappedip as string
        candidates.append({
            "name": name,
            "type": "static-nat",
            "extintf": extintf,
            "extip": extip,
            "mappedip": mappedip,
            "arp-reply": "enable"
        })

    # 2) portforward but mappedip inside list (string list)
    if port is not None:
        candidates.append({
            "name": name,
            "type": "portforward",
            "extintf": extintf,
            "extip": extip,
            "mappedip": [mappedip],
            "extport": str(port),
            "mappedport": str(port),
            "protocol": protocol,
            "arp-reply": "enable"
        })

    # 3) static-nat with mappedip as list of one string (some versions accept)
    candidates.append({
        "name": name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": extip,
        "mappedip": [mappedip],
        "arp-reply": "enable"
    })

    # 4) mappedip as object with "range" key (used by some clients)
    if port is not None:
        candidates.append({
            "name": name,
            "type": "portforward",
            "extintf": extintf,
            "extip": extip,
            "mappedip": [{"range": mappedip}],
            "extport": str(port),
            "mappedport": str(port),
            "protocol": protocol,
            "arp-reply": "enable"
        })
    candidates.append({
        "name": name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": extip,
        "mappedip": [{"range": mappedip}],
        "arp-reply": "enable"
    })

    # 5) mappedip as "start end" string (some exports show "ip mask" or "start end")
    # try "mappedip": "10.10.10.10 10.10.10.10"
    if port is not None:
        candidates.append({
            "name": name,
            "type": "portforward",
            "extintf": extintf,
            "extip": extip,
            "mappedip": f"{mappedip} {mappedip}",
            "extport": str(port),
            "mappedport": str(port),
            "protocol": protocol,
            "arp-reply": "enable"
        })
    candidates.append({
        "name": name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": extip,
        "mappedip": f"{mappedip} {mappedip}",
        "arp-reply": "enable"
    })

    # try candidates in order
    for payload in candidates:
        tried.append(payload)
        res = _try_post(api, payload)
        if res.get("ok"):
            return {"ok": True, "resp": res["resp"], "tried": tried, "errors": errors}
        else:
            errors.append(res)

        # small pause before next attempt
        time.sleep(0.15)

    # if none worked, return aggregated errors
    return {"ok": False, "tried": tried, "errors": errors}


def create_vip_group(api: FortigateAPIHelper, group_name: str, members: list):
    payload = {
        "name": group_name,
        "member": [{"name": m} for m in members]
    }
    try:
        resp = api.post('firewall/vipgrp', payload)
        return {"ok": True, "resp": resp}
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except Exception:
            body = resp.text if resp is not None else str(he)
        logger.error("VIP group creation HTTPError: %s %s", getattr(resp, "status_code", "?"), body)
        return {"ok": False, "status": getattr(resp, "status_code", None), "body": body}
    except Exception as e:
        logger.exception("VIP group creation failed")
        return {"ok": False, "error": str(e)}


def create_policy(api: FortigateAPIHelper, name: str, srcintf: str, dstintf: str, dstaddr: str, service: str, action: str):
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
        return {"ok": True, "resp": resp}
    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except Exception:
            body = resp.text if resp is not None else str(he)
        logger.error("Policy creation HTTPError: %s %s", getattr(resp, "status_code", "?"), body)
        return {"ok": False, "status": getattr(resp, "status_code", None), "body": body}
    except Exception as e:
        logger.exception("Policy creation failed")
        return {"ok": False, "error": str(e)}


def yes_no(prompt: str) -> bool:
    return input(prompt).strip().lower() in ('y', 'yes')


def main():
    print("\n=== Phase 4 – Automated VIP Publish (final + fallback) ===\n")

    api = FortigateAPIHelper(BASE_URL, TOKEN, vdom=VDOM)

    raw_pairs = input("Enter IP:PORT pairs (comma separated) [e.g. 10.10.10.10:80,10.10.10.11:443]:\n> ").strip()
    try:
        ips_ports = parse_ip_ports(raw_pairs)
    except Exception as e:
        print("Invalid IP:PORT input:", e)
        return

    ext_ip = input("External IP (extip): ").strip()
    if not validate_ip(ext_ip):
        print("❌ Invalid External IP (extip).")
        return

    interfaces = get_interfaces(api)
    ext_intf = input("External interface [wan1]: ").strip() or "wan1"
    if interfaces and ext_intf not in interfaces:
        print(f"❌ External interface '{ext_intf}' not found on device (available: {interfaces})")
        return

    vipgrp_name = input("VIP Group name [AUTO_VIP_GRP]: ").strip() or "AUTO_VIP_GRP"
    policy_name = input("Policy name [AUTO_PUBLISH_POLICY]: ").strip() or "AUTO_PUBLISH_POLICY"
    src_intf = input("Source interface [lan]: ").strip() or "lan"
    dst_intf = input("Destination interface [wan1]: ").strip() or "wan1"
    service = input("Service [ALL]: ").strip() or "ALL"
    action = input("Action [accept]: ").strip() or "accept"

    dry_run = yes_no("Dry run mode? (y/n): ")

    results = {"vips": [], "vip_group": None, "policy": None, "errors": []}
    vip_names = []

    print("\n--- Creating VIPs ---")
    for mapped_ip, port in ips_ports:
        vip_name = f"VIP_{mapped_ip.replace('.', '_')}_{port}"

        try:
            if vip_exists(api, vip_name):
                logger.info("VIP exists: %s", vip_name)
                vip_names.append(vip_name)
                results["vips"].append({"name": vip_name, "status": "exists"})
                continue
        except Exception as e:
            results["errors"].append({"vip": vip_name, "error": f"existence_check_failed: {e}"})
            continue

        logger.info("Creating VIP %s → %s:%s", vip_name, mapped_ip, port)

        if dry_run:
            vip_names.append(vip_name)
            results["vips"].append({"name": vip_name, "status": "dry-run"})
            continue

        res = create_vip_with_fallback(api, vip_name, ext_ip, mapped_ip, port=port, extintf=ext_intf)
        if res.get("ok"):
            vip_names.append(vip_name)
            results["vips"].append({"name": vip_name, "status": "created", "response": res.get("resp")})
        else:
            results["errors"].append({"vip": vip_name, "result": res})
        time.sleep(0.2)

    if not vip_names:
        logger.error("No VIPs created. Aborting.")
        results["message"] = "no_vips_created"
        with open("phase4_result.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print("No VIPs were created. See phase4_result.json for details.")
        return

    print("\n--- Creating VIP Group ---")
    if dry_run:
        results["vip_group"] = {"name": vipgrp_name, "status": "dry-run"}
    else:
        grp_res = create_vip_group(api, vipgrp_name, vip_names)
        if grp_res.get("ok"):
            results["vip_group"] = {"name": vipgrp_name, "status": "created", "response": grp_res["resp"]}
        else:
            results["errors"].append({"vip_group": grp_res})
            with open("phase4_result.json", "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print("VIP Group creation failed. Check phase4_result.json")
            return

    print("\n--- Creating Firewall Policy ---")
    if dry_run:
        results["policy"] = {"name": policy_name, "status": "dry-run"}
    else:
        pol_res = create_policy(api, policy_name, src_intf, dst_intf, vipgrp_name, service, action)
        if pol_res.get("ok"):
            results["policy"] = {"name": policy_name, "status": "created", "response": pol_res["resp"]}
        else:
            results["errors"].append({"policy": pol_res})

    with open("phase4_result.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("\n=== Phase 4 Summary ===")
    print(f"VIPs processed : {len(vip_names)}")
    print(f"VIP Group      : {vipgrp_name}")
    print(f"Policy         : {policy_name}")
    print(f"Errors         : {len(results['errors'])}")
    print("\n✔ Results saved to phase4_result.json\n")


if __name__ == '__main__':
    main()
