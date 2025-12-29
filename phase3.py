#!/usr/bin/env python3
# phase3.py (Fixed Version)

import json
import requests
from fortigate_api_helper import FortigateAPIHelper, logger


def create_vip(api, vip_name, ext_ip, mapped_ip, extintf="any"):
    """
    Create VIP with correct mappedip format
    """
    # ✅ FIX: Use correct format for mappedip (IP range)
    vip_data = {
        "name": vip_name,
        "type": "static-nat",
        "extintf": extintf,
        "extip": ext_ip,
        "mappedip": [{"range": f"{mapped_ip}-{mapped_ip}"}],  # Must be range format
        "arp-reply": "enable"
    }

    try:
        resp = api.post("firewall/vip", vip_data)

        if resp.get("status") == "success":
            logger.info(f"✅ VIP '{vip_name}' created successfully.")
        else:
            logger.error(f"❌ Failed to create VIP '{vip_name}': {resp}")

        return resp
    
    except requests.exceptions.HTTPError as he:
        # Handle HTTP errors
        resp = he.response
        try:
            body = resp.json()
        except:
            body = resp.text if resp else str(he)
        
        logger.error(f"❌ VIP creation failed - HTTP {resp.status_code}: {body}")
        return {"status": "error", "http_status": resp.status_code, "error": body}
    
    except Exception as e:
        logger.exception("❌ VIP creation failed")
        return {"status": "error", "error": str(e)}


def update_policy(api, policy_id, vip_name):
    """
    Add VIP to destination address of firewall policy
    """
    try:
        # ✅ FIX: Correct endpoint for getting single policy
        policy_resp = api.get(f"firewall/policy/{policy_id}")
        
        # For single policy get, result is directly in response
        if 'results' in policy_resp:
            results = policy_resp['results']
            if not results:
                logger.error(f"❌ Policy ID {policy_id} not found.")
                return {"status": "error", "message": f"Policy {policy_id} not found"}
            policy = results[0]
        else:
            # Direct response without 'results' wrapper
            policy = policy_resp

        # Get existing dstaddr
        dstaddr = policy.get("dstaddr", [])

        # Check if VIP already exists
        if any(addr.get("name") == vip_name for addr in dstaddr):
            logger.info(f"ℹ️  VIP '{vip_name}' already exists in policy {policy_id}.")
            return {"status": "success", "message": "VIP already attached"}

        # Add VIP
        dstaddr.append({"name": vip_name})

        update_data = {
            "dstaddr": dstaddr,
            "nat": "disable"
        }

        resp = api.put(f"firewall/policy/{policy_id}", update_data)

        if resp.get("status") == "success":
            logger.info(f"✅ Policy {policy_id} updated with VIP '{vip_name}'.")
        else:
            logger.error(f"❌ Failed to update policy {policy_id}: {resp}")

        return resp

    except requests.exceptions.HTTPError as he:
        resp = he.response
        try:
            body = resp.json()
        except:
            body = resp.text if resp else str(he)
        
        logger.error(f"❌ Policy update failed - HTTP {resp.status_code}: {body}")
        return {"status": "error", "http_status": resp.status_code, "error": body}
    
    except Exception as e:
        logger.exception("❌ Policy update failed")
        return {"status": "error", "error": str(e)}


def main():
    fortigate_ip = "192.168.55.238"
    token = "f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9"
    vdom = "root"

    base_url = f"http://{fortigate_ip}/api/v2/cmdb"

    try:
        api = FortigateAPIHelper(
            base_url=base_url,
            token=token,
            vdom=vdom
        )

        print("\n=== Phase 3: Create VIP & Update Policy ===\n")

        vip_name = input("VIP name: ").strip()
        if not vip_name:
            print("❌ VIP name cannot be empty")
            return 1

        ext_ip = input("External IP (extip): ").strip()
        if not api.validate_ip(ext_ip):
            print("❌ Invalid External IP")
            return 1

        mapped_ip = input("Mapped/Internal IP: ").strip()
        if not api.validate_ip(mapped_ip):
            print("❌ Invalid Mapped IP")
            return 1

        extintf = input("External interface (extintf) [any]: ").strip() or "any"
        
        policy_id_str = input("Firewall Policy ID: ").strip()
        try:
            policy_id = int(policy_id_str)
        except ValueError:
            print("❌ Invalid Policy ID (must be a number)")
            return 1

        # Create VIP
        print("\n--- Creating VIP ---")
        vip_resp = create_vip(api, vip_name, ext_ip, mapped_ip, extintf)
        
        # Update Policy
        print("\n--- Updating Policy ---")
        policy_resp = update_policy(api, policy_id, vip_name)

        # Save results
        output = {
            "vip_creation": vip_resp,
            "policy_update": policy_resp
        }

        with open("phase3_result.json", "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4, ensure_ascii=False)

        logger.info("✅ Phase 3 output saved to phase3_result.json")
        
        print("\n=== Phase 3 Summary ===")
        print(f"VIP Creation: {vip_resp.get('status', 'unknown')}")
        print(f"Policy Update: {policy_resp.get('status', 'unknown')}")

    except Exception as e:
        logger.exception("❌ Phase 3 failed")
        print(f"\n❌ Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())