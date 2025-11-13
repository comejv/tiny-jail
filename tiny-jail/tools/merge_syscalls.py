#!/usr/bin/env python3
"""
Merge abstract syscalls with actual syscall numbers for seccomp rules.
Preserves conditions for argument filtering.
"""

import json
from typing import Dict, List, Set, Optional


def load_json(filename: str) -> dict:
    """Load JSON file"""
    with open(filename, "r") as f:
        return json.load(f)


def create_syscall_lookup(syscalls: List[Dict]) -> Dict[str, int]:
    """Create a mapping from syscall name to number"""
    return {sc["name"]: sc["number"] for sc in syscalls}


def resolve_abstract_to_concrete(
    abstract_name: str, abstract_syscalls: Dict, visited: Set[str] = None
) -> List[Dict]:
    """
    Recursively resolve an abstract syscall to concrete syscalls with their conditions.
    Returns list of {base_name, condition, call} entries.
    """
    if visited is None:
        visited = set()

    # Avoid infinite recursion
    if abstract_name in visited:
        return []
    visited.add(abstract_name)

    concrete = []

    if abstract_name not in abstract_syscalls:
        # It's already a concrete syscall
        return [{"base_name": abstract_name, "condition": None}]

    group = abstract_syscalls[abstract_name]
    for impl in group.get("implementations", []):
        base_name = impl.get("base_name")
        if not base_name:
            continue

        # Check if base_name is another abstract syscall
        if base_name in abstract_syscalls:
            # Recursively resolve
            resolved = resolve_abstract_to_concrete(
                base_name, abstract_syscalls, visited.copy()
            )
            concrete.extend(resolved)
        else:
            # It's a concrete syscall - preserve condition
            concrete.append(
                {
                    "base_name": base_name,
                    "condition": impl.get("condition"),
                    "call": impl.get("call"),
                }
            )

    return concrete


def parse_condition(condition: str) -> Optional[Dict]:
    """
    Parse a condition string into a structured format for seccomp.

    Examples:
    - "(flags & (O_WRONLY | O_APPEND | O_TRUNC))"
    - "path = fdToName(fd)"
    - "return_value = euid"

    Returns structured condition or None if unparseable.
    """
    if not condition:
        return None

    condition = condition.strip()

    # Pattern: (arg & flags)
    import re

    # Bitwise AND check: (flags & (O_WRONLY | O_APPEND))
    match = re.match(r"\((\w+)\s*&\s*\((.*?)\)\)", condition)
    if match:
        arg_name = match.group(1)
        flags = match.group(2)
        return {
            "type": "bitwise_and",
            "argument": arg_name,
            "flags": flags,
            "raw": condition,
        }

    # Equality check: path = fdToName(fd)
    match = re.match(r"(\w+)\s*=\s*(.*)", condition)
    if match:
        arg_name = match.group(1)
        value = match.group(2)
        return {
            "type": "equality",
            "argument": arg_name,
            "value": value,
            "raw": condition,
        }

    # Return raw condition if we can't parse it
    return {"type": "raw", "raw": condition}


def merge_syscalls(abstract_file: str, concrete_file: str) -> Dict:
    """
    Merge abstract syscall groups with concrete syscall numbers.
    Preserves conditions for seccomp argument filtering.
    """

    # Load both files
    abstract_syscalls = load_json(abstract_file)
    concrete_syscalls = load_json(concrete_file)

    # Create lookup
    syscall_lookup = create_syscall_lookup(concrete_syscalls)

    # Build merged structure
    merged = {"abstract_groups": {}, "syscalls": {}}

    # Process abstract groups
    for group_name, group_data in abstract_syscalls.items():
        # Resolve to concrete syscalls
        resolved = resolve_abstract_to_concrete(group_name, abstract_syscalls)

        rules = []
        for entry in resolved:
            base_name = entry["base_name"]

            if base_name in syscall_lookup:
                rule = {
                    "name": base_name,
                    "number": syscall_lookup[base_name],
                    "call": entry.get("call"),
                }

                # Parse and add condition if present
                if entry.get("condition"):
                    parsed = parse_condition(entry["condition"])
                    if parsed:
                        rule["condition"] = parsed

                rules.append(rule)

        if rules:  # Only add if we found concrete syscalls
            merged["abstract_groups"][group_name] = {
                "description": group_data.get("description", ""),
                "parameters": group_data.get("parameters", ""),
                "rules": rules,
            }

    # Add all concrete syscalls as simple name -> number mapping
    for sc in concrete_syscalls:
        merged["syscalls"][sc["name"]] = {"number": sc["number"], "abi": sc["abi"]}

    return merged


def main():
    import sys

    if len(sys.argv) != 3:
        print(
            "Usage: python3 merge_syscalls.py <abstract_syscalls.json> <syscalls.json>"
        )
        sys.exit(1)

    abstract_file = sys.argv[1]
    concrete_file = sys.argv[2]

    # Merge the data
    merged = merge_syscalls(abstract_file, concrete_file)

    # Save merged data
    with open("seccomp_data.json", "w") as f:
        json.dump(merged, f, indent=2)

    # Print statistics
    print(f"✓ Merged syscall data")
    print(f"✓ Abstract groups: {len(merged['abstract_groups'])}")
    print(f"✓ Total syscalls: {len(merged['syscalls'])}")
    print(f"✓ Saved to: seccomp_data.json")

    # Show examples with conditions
    print("\nExample abstract groups with conditions:")
    for group_name in ["WriteOpen", "ReadOpen", "chmod_2"]:
        if group_name in merged["abstract_groups"]:
            group = merged["abstract_groups"][group_name]
            print(f"\n  {group_name}: {group['description']}")
            for rule in group["rules"]:
                condition_str = ""
                if "condition" in rule:
                    condition_str = f" [condition: {rule['condition']['raw']}]"
                print(f"    - {rule['name']} (#{rule['number']}){condition_str}")

    # Count rules with conditions
    total_rules = 0
    rules_with_conditions = 0
    for group in merged["abstract_groups"].values():
        for rule in group["rules"]:
            total_rules += 1
            if "condition" in rule:
                rules_with_conditions += 1

    print(f"\n✓ Total rules: {total_rules}")
    print(f"✓ Rules with conditions: {rules_with_conditions}")


if __name__ == "__main__":
    main()
