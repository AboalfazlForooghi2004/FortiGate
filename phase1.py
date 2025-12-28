#!/usr/bin/env python3
# pretty_fortigate.py

import json
from pathlib import Path

INPUT = Path("fortigate_data.json")


def summarize_address(a):
    if a.get("subnet"):
        return a["subnet"]
    if a.get("start-ip") and a.get("end-ip"):
        return f'{a["start-ip"]} - {a["end-ip"]}'
    if a.get("fqdn"):
        return a["fqdn"]
    if a.get("type"):
        return a["type"]
    return ""


def trim(s, width=60):
    s = str(s)
    return s if len(s) <= width else s[: width - 3] + "..."


def print_table(rows, headers):
    col_widths = []
    for i, h in enumerate(headers):
        col_widths.append(
            max(len(h), *(len(trim(r[i])) for r in rows))
        )

    sep = "  "
    header_line = sep.join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    for r in rows:
        print(sep.join(trim(c).ljust(w) for c, w in zip(r, col_widths)))

    print()


def main():
    if not INPUT.exists():
        print("❌ fortigate_data.json پیدا نشد")
        return

    data = json.loads(INPUT.read_text(encoding="utf-8"))

    addresses = data.get("addresses", [])
    groups = data.get("groups", [])
    summary = data.get("summary", {})

    # ================= SUMMARY =================
    print("\n=== Fortigate Export Summary ===")
    print(f"Addresses      : {len(addresses)}")
    print(f"Address Groups : {len(groups)}")
    for k, v in summary.items():
        print(f"{k:15s}: {v}")
    print("================================\n")

    # ================= ADDRESSES =================
    addr_rows = []
    for a in addresses:
        name = a.get("name", "<no-name>")
        addr_type = a.get("type", "unknown")
        value = summarize_address(a)
        comment = a.get("comment") or a.get("uuid") or ""
        addr_rows.append([name, addr_type, value, comment])

    if addr_rows:
        print("Addresses:")
        print_table(
            addr_rows,
            ["NAME", "TYPE", "VALUE", "COMMENT / UUID"]
        )
    else:
        print("No addresses found.\n")

    # ================= GROUPS =================
    grp_rows = []
    for g in groups:
        name = g.get("name", "<no-name>")
        members = g.get("member", [])

        member_names = []
        for m in members:
            if isinstance(m, dict):
                member_names.append(m.get("name", "<unknown>"))
            else:
                member_names.append(str(m))

        members_s = ", ".join(member_names)
        grp_rows.append([name, members_s])

    if grp_rows:
        print("Address Groups:")
        print_table(
            grp_rows,
            ["GROUP NAME", "MEMBERS"]
        )
    else:
        print("No address groups found.\n")


if __name__ == "__main__":
    main()
