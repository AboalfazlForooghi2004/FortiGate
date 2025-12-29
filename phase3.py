#!/usr/bin/env python3
# phase3.py

import json
from fortigate_api_helper import FortigateAPIHelper, logger


def create_vip(api, vip_name, ext_ip, mapped_ip, extintf="any"):
    vip_data = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [{"range": mapped_ip}],
        "arp-reply": "enable"
    }

    resp = api.post("firewall/vip", vip_data)

    if resp.get("status") == "success":
        logger.info(f"VIP '{vip_name}' created successfully.")
    else:
        logger.error(f"Failed to create VIP '{vip_name}': {resp}")

    return resp


def update_policy(api, policy_id, vip_name):
    """
    Add VIP to destination address of firewall policy
    """

    # ---- get policy ----
    policy_resp = api.get("firewall/policy", params={"policyid": policy_id})
    results = policy_resp.get("results", [])

    if not results:
        logger.error(f"Policy ID {policy_id} not found in this VDOM.")
        return None

    policy = results[0]

    # ---- existing dstaddr ----
    dstaddr = policy.get("dstaddr", [])

    # check if VIP already exists
    if any(addr.get("name") == vip_name for addr in dstaddr):
        logger.info(f"VIP '{vip_name}' already exists in policy {policy_id}.")
        return {"status": "success", "message": "VIP already attached"}

    # add VIP
    dstaddr.append({"name": vip_name})

    update_data = {
        "dstaddr": dstaddr,
        "nat": "disable"
    }

    resp = api.put(f"firewall/policy/{policy_id}", update_data)

    if resp.get("status") == "success":
        logger.info(f"Policy {policy_id} updated with VIP '{vip_name}'.")
    else:
        logger.error(f"Failed to update policy {policy_id}: {resp}")

    return resp


def main():
    fortigate_ip = "192.168.55.238"
    token = "f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9"
    vdom = "root"

    base_url = f"http://{fortigate_ip}/api/v2/cmdb"

    api = FortigateAPIHelper(
        base_url=base_url,
        token=token,
        vdom=vdom
    )

    print("\n=== Phase 3: Create VIP & Update Policy ===\n")

    vip_name = input("VIP name: ").strip()
    ext_ip = input("External IP (extip): ").strip()
    mapped_ip = input("Mapped/Internal IP: ").strip()
    extintf = input("External interface (extintf) [any]: ").strip() or "any"
    policy_id = int(input("Firewall Policy ID: ").strip())

    vip_resp = create_vip(api, vip_name, ext_ip, mapped_ip, extintf)
    policy_resp = update_policy(api, policy_id, vip_name)

    output = {
        "vip_creation": vip_resp,
        "policy_update": policy_resp
    }

    with open("phase3_result.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    logger.info("Phase 3 output saved to phase3_result.json")


if __name__ == "__main__":
    main()
