#!/usr/bin/env python3
"""
Extract syscall information from markdown table into JSON/YAML
"""

import re
import json
import yaml
from typing import List, Dict, Optional


def parse_syscall_markdown(content: str) -> List[Dict]:
    """
    Parse syscall table from markdown content.

    Expected format:
    | Num | ABI | Name | Entry Point | noreturn |
    | 0 | common | read | sys_read | - |
    """
    syscalls = []

    # Split into lines
    lines = content.split("\n")

    # Find the table header
    in_table = False
    header_found = False

    for line in lines:
        line = line.strip()

        # Check if this is the header line
        if "| Num" in line and "| ABI" in line and "| Name" in line:
            header_found = True
            in_table = True
            continue

        # Skip separator line
        if in_table and "---" in line:
            continue

        # Parse data rows
        if in_table and line.startswith("|"):
            # Split by pipe and clean up
            parts = [p.strip() for p in line.split("|")]

            # Filter empty strings from leading/trailing pipes
            parts = [p for p in parts if p]

            # Need at least 4 columns: num, abi, name, entry_point
            if len(parts) >= 4:
                try:
                    # Check if first part is a number (skip if it's "...")
                    if parts[0] == "...":
                        continue

                    num = int(parts[0])
                    abi = parts[1]
                    name = parts[2]
                    entry_point = parts[3]

                    # Optional fields
                    compat_entry = parts[4] if len(parts) > 4 else None
                    noreturn = parts[5] if len(parts) > 5 else None

                    # Clean up optional fields
                    if compat_entry == "-":
                        compat_entry = None
                    if noreturn == "-":
                        noreturn = None

                    syscall = {
                        "number": num,
                        "abi": abi,
                        "name": name,
                        "entry_point": entry_point,
                    }

                    if compat_entry:
                        syscall["compat_entry_point"] = compat_entry
                    if noreturn:
                        syscall["noreturn"] = True

                    syscalls.append(syscall)

                except (ValueError, IndexError):
                    # Skip malformed lines
                    continue

        # Check if we've left the table
        elif in_table and not line.startswith("|") and line:
            break

    return syscalls


def parse_alternative_format(content: str) -> List[Dict]:
    """
    Alternative parser for format: <number> <abi> <name> <entry point> [<compat> [noreturn]]
    """
    syscalls = []

    # Pattern: number abi name entry_point [compat] [noreturn]
    pattern = r"^(\d+)\s+(\w+)\s+(\w+)\s+(\w+)(?:\s+(\w+))?(?:\s+(noreturn))?"

    for line in content.split("\n"):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        match = re.match(pattern, line)
        if match:
            num, abi, name, entry_point, compat, noreturn = match.groups()

            syscall = {
                "number": int(num),
                "abi": abi,
                "name": name,
                "entry_point": entry_point,
            }

            if compat:
                syscall["compat_entry_point"] = compat
            if noreturn:
                syscall["noreturn"] = True

            syscalls.append(syscall)

    return syscalls


def main():
    import sys

    # Read input file
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        with open(input_file, "r") as f:
            content = f.read()
    else:
        print("Reading from stdin (paste your markdown and press Ctrl+D when done)...")
        content = sys.stdin.read()

    # Try markdown table format first
    syscalls = parse_syscall_markdown(content)

    # If no syscalls found, try alternative format
    if not syscalls:
        syscalls = parse_alternative_format(content)

    if not syscalls:
        print("Error: No syscalls found in input", file=sys.stderr)
        sys.exit(1)

    # Sort by number
    syscalls.sort(key=lambda x: x["number"])

    # Output as JSON
    with open("syscalls.json", "w") as f:
        json.dump(syscalls, f, indent=2)

    # Output as YAML
    with open("syscalls.yaml", "w") as f:
        yaml.dump(syscalls, f, default_flow_style=False)

    # Output as simple list (just names)
    with open("syscalls.txt", "w") as f:
        for sc in syscalls:
            f.write(f"{sc['name']}\n")

    # Print summary
    print(f"✓ Extracted {len(syscalls)} syscalls")
    print(f"✓ Saved to: syscalls.json, syscalls.yaml, syscalls.txt")

    # Print by ABI
    abi_counts = {}
    for sc in syscalls:
        abi_counts[sc["abi"]] = abi_counts.get(sc["abi"], 0) + 1

    print("\nBreakdown by ABI:")
    for abi, count in sorted(abi_counts.items()):
        print(f"  {abi}: {count}")

    # Show first few entries
    print("\nFirst 5 syscalls:")
    for sc in syscalls[:5]:
        print(f"  {sc['number']:3d} {sc['abi']:8s} {sc['name']}")

    # Show last few entries
    print("\nLast 5 syscalls:")
    for sc in syscalls[-5:]:
        print(f"  {sc['number']:3d} {sc['abi']:8s} {sc['name']}")


if __name__ == "__main__":
    main()
