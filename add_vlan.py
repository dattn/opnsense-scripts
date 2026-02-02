#!/usr/bin/env python3
"""
Add a VLAN to OPNsense configuration.

This script interactively prompts for VLAN details and creates:
1. A new VLAN entry in the <vlans> section
2. A new interface assignment in <interfaces> (as next available optX)

Usage:
    python3 add_vlan.py <input_config.xml> [output_config.xml]

If output_config.xml is not specified, the modified config is written to stdout.

Author: Generated for OPNsense configuration management
"""

import ipaddress
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class VlanConfig:
    """Configuration for a new VLAN."""
    parent_interface: str       # Physical interface (e.g., "igb1")
    tag: int                    # VLAN ID (1-4094)
    description: str = ""       # Optional description
    pcp: int = 0                # Priority Code Point (0-7)
    proto: str = ""             # Protocol (empty = 802.1Q)

    @property
    def vlanif(self) -> str:
        """Generate VLAN interface name."""
        return f"{self.parent_interface}_vlan{self.tag}"


@dataclass
class InterfaceConfig:
    """Configuration for assigning VLAN to an interface."""
    name: str                   # Interface name (e.g., "opt6")
    vlanif: str                 # VLAN interface (e.g., "igb1_vlan200")
    description: str            # Human-readable name
    ipaddr: str                 # IP address (e.g., "192.168.200.1")
    subnet: int = 24            # CIDR subnet mask
    enable: bool = True
    lock: bool = True


def get_text(element: Optional[ET.Element], default: str = "") -> str:
    """Safely get text content from an XML element."""
    if element is None:
        return default
    return element.text or default


def generate_uuid() -> str:
    """Generate a UUID for new config entries."""
    return str(uuid.uuid4())


def indent_xml(elem: ET.Element, level: int = 0) -> None:
    """Add indentation to XML elements for pretty printing."""
    indent = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        last_child = None
        for child in elem:
            indent_xml(child, level + 1)
            last_child = child
        if last_child is not None and (not last_child.tail or not last_child.tail.strip()):
            last_child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent


# =============================================================================
# Validation Functions
# =============================================================================

def load_config(path: Path) -> tuple[ET.ElementTree, ET.Element]:
    """
    Load and validate an OPNsense config file.
    
    Returns:
        Tuple of (tree, root element)
    
    Raises:
        SystemExit on error
    """
    if not path.exists():
        print(f"Error: File '{path}' does not exist", file=sys.stderr)
        sys.exit(1)

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    if root.tag != "opnsense":
        print(f"Error: Root element is '{root.tag}', expected 'opnsense'", file=sys.stderr)
        sys.exit(1)

    return tree, root


def get_physical_interfaces(root: ET.Element) -> list[str]:
    """
    Get list of physical interfaces from the config.
    
    Looks at interfaces section and extracts base interface names
    (ignoring VLANs, virtual interfaces, etc.)
    """
    interfaces_elem = root.find("interfaces")
    if interfaces_elem is None:
        return []

    physical = set()
    for iface in interfaces_elem:
        if_name = get_text(iface.find("if"))
        if not if_name:
            continue
        # Extract base interface (strip VLAN suffix, ignore virtual)
        if if_name.startswith(("lo", "pppoe", "openvpn", "wg", "wireguard")):
            continue
        # Get base interface name
        base = if_name.split("_vlan")[0]
        if base and re.match(r'^[a-z]+\d+$', base):
            physical.add(base)

    return sorted(physical)


def get_existing_vlans(root: ET.Element) -> list[tuple[str, int]]:
    """
    Get list of existing VLANs as (parent_interface, tag) tuples.
    """
    vlans_elem = root.find("vlans")
    if vlans_elem is None:
        return []

    existing = []
    for vlan in vlans_elem.findall("vlan"):
        parent = get_text(vlan.find("if"))
        tag_text = get_text(vlan.find("tag"))
        if parent and tag_text:
            try:
                existing.append((parent, int(tag_text)))
            except ValueError:
                pass

    return existing


def validate_vlan_unique(root: ET.Element, parent_if: str, tag: int) -> bool:
    """
    Check if a VLAN tag is unique on the given parent interface.
    
    Returns:
        True if VLAN is unique, False if it already exists
    """
    existing = get_existing_vlans(root)
    return (parent_if, tag) not in existing


def get_existing_opt_numbers(root: ET.Element) -> list[int]:
    """
    Get list of existing opt interface numbers.
    """
    interfaces_elem = root.find("interfaces")
    if interfaces_elem is None:
        return []

    numbers = []
    for iface in interfaces_elem:
        if iface.tag.startswith("opt"):
            try:
                num = int(iface.tag[3:])
                numbers.append(num)
            except ValueError:
                pass

    return sorted(numbers)


def find_next_opt_name(root: ET.Element) -> str:
    """
    Find the next available opt interface name.
    """
    existing = get_existing_opt_numbers(root)
    if not existing:
        return "opt1"

    # Find the first gap or use max+1
    for i in range(1, max(existing) + 2):
        if i not in existing:
            return f"opt{i}"

    return f"opt{max(existing) + 1}"


def validate_ip_address(ip_str: str) -> bool:
    """Validate an IPv4 address string."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_subnet(subnet_str: str) -> bool:
    """Validate a CIDR subnet mask (1-32)."""
    try:
        subnet = int(subnet_str)
        return 1 <= subnet <= 32
    except ValueError:
        return False


# =============================================================================
# Element Creation Functions
# =============================================================================

def create_vlan_element(vlan: VlanConfig) -> ET.Element:
    """Create a VLAN XML element."""
    elem = ET.Element("vlan")
    elem.set("uuid", generate_uuid())

    ET.SubElement(elem, "if").text = vlan.parent_interface
    ET.SubElement(elem, "tag").text = str(vlan.tag)
    ET.SubElement(elem, "pcp").text = str(vlan.pcp)
    ET.SubElement(elem, "proto").text = vlan.proto
    ET.SubElement(elem, "descr").text = vlan.description
    ET.SubElement(elem, "vlanif").text = vlan.vlanif

    return elem


def create_interface_element(iface: InterfaceConfig) -> ET.Element:
    """Create an interface XML element."""
    elem = ET.Element(iface.name)

    ET.SubElement(elem, "if").text = iface.vlanif
    ET.SubElement(elem, "descr").text = iface.description
    ET.SubElement(elem, "enable").text = "1" if iface.enable else "0"
    ET.SubElement(elem, "lock").text = "1" if iface.lock else "0"
    ET.SubElement(elem, "spoofmac").text = ""
    ET.SubElement(elem, "ipaddr").text = iface.ipaddr
    ET.SubElement(elem, "subnet").text = str(iface.subnet)

    return elem


# =============================================================================
# Config Modification Functions
# =============================================================================

def add_vlan_to_config(root: ET.Element, vlan: VlanConfig) -> None:
    """Add a VLAN to the <vlans> section."""
    vlans_elem = root.find("vlans")
    if vlans_elem is None:
        vlans_elem = ET.SubElement(root, "vlans")
        vlans_elem.set("version", "1.0.0")
        vlans_elem.set("description", "VLAN configuration")

    vlans_elem.append(create_vlan_element(vlan))


def add_interface_to_config(root: ET.Element, iface: InterfaceConfig) -> None:
    """Add an interface to the <interfaces> section."""
    interfaces_elem = root.find("interfaces")
    if interfaces_elem is None:
        interfaces_elem = ET.SubElement(root, "interfaces")

    interfaces_elem.append(create_interface_element(iface))


# =============================================================================
# Interactive Prompts
# =============================================================================

def prompt(message: str, default: str = "", validator=None, error_msg: str = "Invalid input") -> str:
    """
    Prompt for user input with optional default and validation.
    """
    while True:
        if default:
            print(f"{message} [{default}]: ", end="", file=sys.stderr)
            user_input = input().strip()
            if not user_input:
                user_input = default
        else:
            print(f"{message}: ", end="", file=sys.stderr)
            user_input = input().strip()

        if not user_input and not default:
            print("  This field is required.", file=sys.stderr)
            continue

        if validator and not validator(user_input):
            print(f"  {error_msg}", file=sys.stderr)
            continue

        return user_input


def prompt_for_config(root: ET.Element) -> tuple[VlanConfig, InterfaceConfig]:
    """
    Interactively prompt for VLAN and interface configuration.
    
    Returns:
        Tuple of (VlanConfig, InterfaceConfig)
    """
    print(file=sys.stderr)

    # Get available physical interfaces
    physical_interfaces = get_physical_interfaces(root)
    if physical_interfaces:
        print(f"Available parent interfaces: {', '.join(physical_interfaces)}", file=sys.stderr)
    else:
        print("Warning: Could not detect physical interfaces", file=sys.stderr)

    # Parent interface
    def validate_parent(val: str) -> bool:
        return bool(re.match(r'^[a-z]+\d+$', val))

    parent_if = prompt(
        "Parent interface (e.g., igb1)",
        validator=validate_parent,
        error_msg="Interface should be like 'igb0', 'em1', etc."
    )

    # VLAN tag
    existing_vlans = get_existing_vlans(root)
    existing_on_parent = [tag for (p, tag) in existing_vlans if p == parent_if]
    if existing_on_parent:
        print(f"Existing VLANs on {parent_if}: {', '.join(map(str, sorted(existing_on_parent)))}", file=sys.stderr)

    def validate_tag(val: str) -> bool:
        try:
            tag = int(val)
            if not 1 <= tag <= 4094:
                return False
            if not validate_vlan_unique(root, parent_if, tag):
                print(f"  VLAN {tag} already exists on {parent_if}", file=sys.stderr)
                return False
            return True
        except ValueError:
            return False

    tag = int(prompt(
        "VLAN ID (1-4094)",
        validator=validate_tag,
        error_msg="Must be a number between 1 and 4094, and not already in use"
    ))

    # Description
    description = prompt("Description (e.g., HomeAssistant)", default="")

    # IP address
    ip_addr = prompt(
        "IP address for interface",
        validator=validate_ip_address,
        error_msg="Must be a valid IPv4 address (e.g., 192.168.200.1)"
    )

    # Subnet
    subnet = int(prompt(
        "Subnet (CIDR)",
        default="24",
        validator=validate_subnet,
        error_msg="Must be a number between 1 and 32"
    ))

    # Create configs
    vlan_config = VlanConfig(
        parent_interface=parent_if,
        tag=tag,
        description=description,
    )

    interface_name = find_next_opt_name(root)
    interface_config = InterfaceConfig(
        name=interface_name,
        vlanif=vlan_config.vlanif,
        description=description or f"VLAN{tag}",
        ipaddr=ip_addr,
        subnet=subnet,
    )

    return vlan_config, interface_config


# =============================================================================
# Main
# =============================================================================

def print_usage():
    """Print usage information."""
    print("Usage: python3 add_vlan.py <input_config.xml> [output_config.xml]", file=sys.stderr)
    print(file=sys.stderr)
    print("Add a VLAN to OPNsense configuration.", file=sys.stderr)
    print(file=sys.stderr)
    print("Arguments:", file=sys.stderr)
    print("  input_config.xml   Path to the OPNsense configuration file", file=sys.stderr)
    print("  output_config.xml  Output file path (default: stdout)", file=sys.stderr)


def main():
    # Parse arguments
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_usage()
        sys.exit(0 if len(sys.argv) > 1 else 1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else None

    print("OPNsense VLAN Configuration Tool", file=sys.stderr)
    print("=" * 35, file=sys.stderr)
    print(f"Input:  {input_path}", file=sys.stderr)
    print(f"Output: {output_path if output_path else 'stdout'}", file=sys.stderr)

    # Load and validate config
    tree, root = load_config(input_path)

    # Get VLAN configuration interactively
    vlan_config, interface_config = prompt_for_config(root)

    # Confirm
    print(file=sys.stderr)
    print("Configuration Summary", file=sys.stderr)
    print("-" * 35, file=sys.stderr)
    print(f"  Parent interface: {vlan_config.parent_interface}", file=sys.stderr)
    print(f"  VLAN ID:          {vlan_config.tag}", file=sys.stderr)
    print(f"  VLAN interface:   {vlan_config.vlanif}", file=sys.stderr)
    print(f"  Description:      {vlan_config.description or '(none)'}", file=sys.stderr)
    print(f"  Assigned to:      {interface_config.name}", file=sys.stderr)
    print(f"  IP address:       {interface_config.ipaddr}/{interface_config.subnet}", file=sys.stderr)
    print(file=sys.stderr)

    print("Proceed? [Y/n]: ", end="", file=sys.stderr)
    confirm = input().strip().lower()
    if confirm and confirm not in ("y", "yes"):
        print("Aborted.", file=sys.stderr)
        sys.exit(0)

    # Apply changes
    print(file=sys.stderr)
    print("Creating VLAN...", file=sys.stderr)
    add_vlan_to_config(root, vlan_config)
    print(f"  Added VLAN {vlan_config.tag} on {vlan_config.parent_interface} ({vlan_config.vlanif})", file=sys.stderr)

    add_interface_to_config(root, interface_config)
    print(f"  Assigned to interface {interface_config.name} as \"{interface_config.description}\"", file=sys.stderr)
    print(f"  IP: {interface_config.ipaddr}/{interface_config.subnet}", file=sys.stderr)

    # Pretty print and write
    indent_xml(root)
    if output_path:
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        print(file=sys.stderr)
        print(f"Config written to: {output_path}", file=sys.stderr)
    else:
        tree.write(sys.stdout, encoding="unicode", xml_declaration=True)
        print(file=sys.stderr)  # newline after XML output


if __name__ == "__main__":
    main()
