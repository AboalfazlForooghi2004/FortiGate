import json
from collections import defaultdict
import ipaddress
from fortigate_api_helper import FortigateAPIHelper, logger


def ip_in_address_object(target_ip, addr):
    """Check if target_ip is inside the given Address Object"""
    ip = ipaddress.ip_address(target_ip)

    if addr['type'] == 'subnet' and 'subnet' in addr:
        # Subnet as string: "0.0.0.0 255.255.255.255" or "10.212.134.0/24"
        try:
            if '/' in addr['subnet']:
                net = ipaddress.ip_network(addr['subnet'], strict=False)
            else:
                # format "IP MASK"
                ip_part, mask_part = addr['subnet'].split()
                net = ipaddress.ip_network(f"{ip_part}/{mask_part}", strict=False)
            return ip in net
        except Exception:
            return False

    elif addr['type'] == 'iprange' and 'start-ip' in addr and 'end-ip' in addr:
        start = ipaddress.ip_address(addr['start-ip'])
        end = ipaddress.ip_address(addr['end-ip'])
        return start <= ip <= end

    return False


def find_duplicates(addresses):
    """Find duplicate Address Objects based on type & value"""
    dup_map = defaultdict(list)

    for addr in addresses:
        t = addr.get('type')
        if t == 'subnet' and 'subnet' in addr:
            key = f"subnet:{addr['subnet']}"
        elif t == 'iprange' and 'start-ip' in addr and 'end-ip' in addr:
            key = f"iprange:{addr['start-ip']}-{addr['end-ip']}"
        elif t == 'fqdn' and 'fqdn' in addr:
            key = f"fqdn:{addr['fqdn']}"
        elif t == 'wildcard' and 'wildcard' in addr:
            key = f"wildcard:{addr['wildcard']}"
        else:
            continue

        dup_map[key].append(addr.get('name', '<no-name>'))

    return {k: v for k, v in dup_map.items() if len(v) > 1}


def find_groups_with_ip(groups, addresses, target_ip):
    """Return list of Group names containing target_ip"""
    addr_lookup = {a['name']: a for a in addresses}
    matched_groups = []

    for group in groups:
        for member in group.get('member', []):
            if isinstance(member, dict):
                member_name = member.get('name')
            else:
                member_name = str(member)
            addr = addr_lookup.get(member_name)
            if addr and ip_in_address_object(target_ip, addr):
                matched_groups.append(group.get('name', '<no-name>'))
                break

    return matched_groups


def main():
    fortigate_ip = '192.168.55.238'
    token = 'f1kQf0Q3pjhsw11HmgkcHG5r6s4Qm9'
    base_url = f'http://{fortigate_ip}/api/v2/cmdb/'  

    api = FortigateAPIHelper(base_url, token)

    addresses = api.get('firewall/address').get('results', [])
    groups = api.get('firewall/addrgrp').get('results', [])

    #  Find duplicate Address Objects
    duplicates = find_duplicates(addresses)
    logger.info(f"Duplicate address objects found: {len(duplicates)}")

    #  Input IP and search in groups
    target_ip = input("Enter IP to search in groups: ").strip()
    if not api.validate_ip(target_ip):
        logger.error("Invalid IP address")
        return

    matched_groups = find_groups_with_ip(groups, addresses, target_ip)

    # Output
    print("\n=== Phase 2 Result ===")
    print(f"Duplicate Objects : {len(duplicates)}")
    if duplicates:
        print("Duplicate Address Objects:")
        for k, v in duplicates.items():
            print(f"{k} -> {v}")

    print(f"Groups with IP    : {len(matched_groups)}")
    if matched_groups:
        print("Matched Groups:")
        for g in matched_groups:
            print(f"- {g}")

    # Save JSON
    output = {
        "duplicates": duplicates,
        "ip_search": {
            "ip": target_ip,
            "groups": matched_groups
        }
    }
    with open("phase2_result.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    logger.info("Phase 2 output saved to phase2_result.json")


if __name__ == "__main__":
    main()
