#!/usr/bin/env python3
# phase3.py

import json
from fortigate_api_helper import FortigateAPIHelper, logger


def create_vip(api, vip_name, ext_ip, mapped_ip, extintf="any", port=None):
    """
    Create a VIP object on FortiGate (Static NAT)
    """
    vip_data = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [
            {
                "range": mapped_ip
            }
        ],
        "arp-reply": "enable"
    }

    if port:
        vip_data.update({
            "portforward": "enable",
            "extport": str(port[0]),
            "mappedport": str(port[1])
        })

    resp = api.post("firewall/vip", vip_data)

    if resp.get("status") == "success":
        logger.info(f"VIP '{vip_name}' created successfully.")
    else:
        logger.error(f"Failed to create VIP '{vip_name}': {resp}")

    return resp


def update_policy(api, policy_id, vip_name):
    """
    Update Firewall Policy destination to VIP
    """
    policy_resp = api.get(f"firewall/policy/{policy_id}")
    policy = policy_resp.get("results")

    if not policy:
        logger.error(f"Policy ID {policy_id} not found.")
        return None

    policy["dstaddr"] = [
        {
            "name": vip_name
        }
    ]

    policy["nat"] = "disable"

    resp = api.put(f"firewall/policy/{policy_id}", policy)

    if resp.get("status") == "success":
        logger.info(f"Policy {policy_id} updated with VIP '{vip_name}'.")
    else:
        logger.error(f"Failed to update policy {policy_id}: {resp}")

    return resp


def main():
    # ---------- ثابت‌ها (مثل قبل) ----------
    fortigate_ip = "192.168.55.238"
    token = "f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9"
    vdom = "root"

    base_url = f"https://{fortigate_ip}/api/v2/cmdb"

    api = FortigateAPIHelper(
        base_url=base_url,
        token=token,
        vdom=vdom
    )

    # ---------- ورودی‌های فاز 3 ----------
    print("\n=== Phase 3: Create VIP & Update Policy ===\n")

    vip_name = input("VIP name: ").strip()
    ext_ip = input("External IP (extip): ").strip()
    mapped_ip = input("Mapped/Internal IP: ").strip()
    extintf = input("External interface (extintf) [any]: ").strip() or "any"
    policy_id = int(input("Firewall Policy ID: ").strip())

    # ---------- اجرا ----------
    vip_resp = create_vip(
        api=api,
        vip_name=vip_name,
        ext_ip=ext_ip,
        mapped_ip=mapped_ip,
        extintf=extintf
    )

    policy_resp = update_policy(
        api=api,
        policy_id=policy_id,
        vip_name=vip_name
    )

    # ---------- خروجی ----------
    output = {
        "vip_creation": vip_resp,
        "policy_update": policy_resp
    }

    with open("phase3_result.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    logger.info("Phase 3 output saved to phase3_result.json")


if __name__ == "__main__":
    main()