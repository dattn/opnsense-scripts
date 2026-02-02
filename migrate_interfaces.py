#!/usr/bin/env python3
"""
Migrate OPNsense interface device names to new hardware.

This script helps migrate an OPNsense configuration from one hardware platform
to another where network interface device names have changed (e.g., igb -> igc/ix).

It will:
1. Detect all physical and virtual interfaces in the config
2. Prompt for new device names for each interface
3. Automatically rename VLAN interfaces based on parent changes
4. Update all references in interfaces, VLANs, and PPP sections

Usage:
    python3 migrate_interfaces.py <input_config.xml> [output_config.xml]

If output_config.xml is not specified, the migrated config is written to stdout.

Author: Generated for OPNsense configuration management
"""

import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# =============================================================================
# Constants
# =============================================================================

# Pattern for physical NIC device names (FreeBSD/OPNsense)
PHYSICAL_NIC_PATTERN = re.compile(r'^(igb|igc|ix|ixl|ixv|em|re|bge|cxl|mlx|mce|vmx|vtnet|hn)[0-9]+$')

# Pattern for virtual/special interfaces that may need migration
VIRTUAL_INTERFACE_PATTERN = re.compile(r'^(pppoe|pptp|l2tp|ovpn|wg|tun|tap|gif|gre|vxlan|bridge|lagg)[0-9]*$')

# Pattern for interfaces to always skip (system interfaces)
SKIP_INTERFACE_PATTERN = re.compile(r'^(lo|pflog|pfsync|enc|openvpn|wireguard)[0-9]*$')

# Pattern for VLAN interface names
VLAN_PATTERN = re.compile(r'^(.+)_vlan(\d+)$')


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class InterfaceInfo:
    """Information about a discovered interface."""
    device: str                     # Device name (e.g., "igb0")
    used_by: list[str] = field(default_factory=list)  # Where it's used (e.g., ["LAN", "Guest VLAN 174"])
    is_physical: bool = False
    is_virtual: bool = False
    is_vlan: bool = False
    vlan_parent: str = ""           # For VLANs: parent device
    vlan_tag: int = 0               # For VLANs: tag number


@dataclass
class MigrationMapping:
    """Mapping of old device name to new device name."""
    old_name: str
    new_name: str
    is_auto: bool = False           # True if auto-generated (VLAN rename)


# =============================================================================
# Helper Functions
# =============================================================================

def get_text(element: Optional[ET.Element], default: str = "") -> str:
    """Safely get text content from an XML element."""
    if element is None:
        return default
    return element.text or default


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


def classify_interface(device: str) -> tuple[bool, bool, bool]:
    """
    Classify an interface device name.
    
    Returns:
        Tuple of (is_physical, is_virtual, is_vlan)
    """
    # Check if it's a VLAN
    if VLAN_PATTERN.match(device):
        return (False, False, True)
    
    # Check if it's a physical NIC
    if PHYSICAL_NIC_PATTERN.match(device):
        return (True, False, False)
    
    # Check if it's a virtual interface
    if VIRTUAL_INTERFACE_PATTERN.match(device):
        return (False, True, False)
    
    # Unknown - treat as virtual
    return (False, True, False)


def should_skip_interface(device: str) -> bool:
    """Check if an interface should be skipped entirely."""
    return bool(SKIP_INTERFACE_PATTERN.match(device))


def parse_vlan_interface(device: str) -> tuple[str, int]:
    """
    Parse a VLAN interface name into parent and tag.
    
    Returns:
        Tuple of (parent_device, vlan_tag) or ("", 0) if not a VLAN
    """
    match = VLAN_PATTERN.match(device)
    if match:
        return (match.group(1), int(match.group(2)))
    return ("", 0)


# =============================================================================
# Config Analysis
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


def discover_interfaces(root: ET.Element) -> dict[str, InterfaceInfo]:
    """
    Discover all interfaces referenced in the configuration.
    
    Scans:
    - <interfaces> section for interface assignments
    - <vlans> section for VLAN definitions
    - <ppps> section for PPP/PPPoE configurations
    
    Returns:
        Dict mapping device names to InterfaceInfo objects
    """
    interfaces: dict[str, InterfaceInfo] = {}
    
    def add_interface(device: str, used_by: str = "") -> None:
        """Add or update an interface entry."""
        if not device or should_skip_interface(device):
            return
            
        if device not in interfaces:
            is_physical, is_virtual, is_vlan = classify_interface(device)
            info = InterfaceInfo(
                device=device,
                is_physical=is_physical,
                is_virtual=is_virtual,
                is_vlan=is_vlan,
            )
            if is_vlan:
                info.vlan_parent, info.vlan_tag = parse_vlan_interface(device)
            interfaces[device] = info
        
        if used_by and used_by not in interfaces[device].used_by:
            interfaces[device].used_by.append(used_by)
    
    # Scan <interfaces> section
    interfaces_elem = root.find("interfaces")
    if interfaces_elem is not None:
        for iface in interfaces_elem:
            iface_name = iface.tag  # e.g., "lan", "wan", "opt1"
            device = get_text(iface.find("if"))
            descr = get_text(iface.find("descr"), iface_name.upper())
            
            if device:
                # For VLANs, show both the assignment and the VLAN info
                if VLAN_PATTERN.match(device):
                    parent, tag = parse_vlan_interface(device)
                    add_interface(device, f"{descr} (VLAN {tag})")
                    # Also track the parent
                    add_interface(parent, f"parent of {descr}")
                else:
                    add_interface(device, descr)
    
    # Scan <vlans> section
    vlans_elem = root.find("vlans")
    if vlans_elem is not None:
        for vlan in vlans_elem.findall("vlan"):
            parent = get_text(vlan.find("if"))
            tag = get_text(vlan.find("tag"))
            vlanif = get_text(vlan.find("vlanif"))
            
            if parent:
                add_interface(parent, f"VLAN {tag} parent")
            if vlanif:
                add_interface(vlanif, f"VLAN {tag}")
    
    # Scan <ppps> section
    ppps_elem = root.find("ppps")
    if ppps_elem is not None:
        for ppp in ppps_elem.findall("ppp"):
            ppp_type = get_text(ppp.find("type"), "ppp")
            ports = get_text(ppp.find("ports"))
            
            if ports:
                add_interface(ports, f"{ppp_type.upper()} port")
    
    return interfaces


def get_physical_interfaces(interfaces: dict[str, InterfaceInfo]) -> list[str]:
    """Get sorted list of physical interface device names."""
    return sorted([d for d, info in interfaces.items() if info.is_physical])


def get_virtual_interfaces(interfaces: dict[str, InterfaceInfo]) -> list[str]:
    """Get sorted list of virtual interface device names."""
    return sorted([d for d, info in interfaces.items() if info.is_virtual])


def get_vlan_interfaces(interfaces: dict[str, InterfaceInfo]) -> list[str]:
    """Get sorted list of VLAN interface device names."""
    return sorted([d for d, info in interfaces.items() if info.is_vlan])


# =============================================================================
# Interactive Prompts
# =============================================================================

def prompt_device_migration(device: str, info: InterfaceInfo) -> Optional[str]:
    """
    Prompt user for new device name.
    
    Returns:
        New device name, or None to keep unchanged
    """
    usage = ", ".join(info.used_by) if info.used_by else "(unused)"
    print(f"\n{device} (used by: {usage})", file=sys.stderr)
    
    while True:
        print(f"  New name [{device}]: ", end="", file=sys.stderr)
        new_name = input().strip()
        
        if not new_name:
            return None  # Keep unchanged
        
        if new_name == device:
            return None  # Same name, no change
        
        # Validate the new name follows device naming pattern
        if info.is_physical and not PHYSICAL_NIC_PATTERN.match(new_name):
            print(f"  Warning: '{new_name}' doesn't look like a physical NIC name", file=sys.stderr)
            print("  Use anyway? [y/N]: ", end="", file=sys.stderr)
            confirm = input().strip().lower()
            if confirm not in ("y", "yes"):
                continue
        
        return new_name


def prompt_virtual_migration(device: str, info: InterfaceInfo) -> Optional[str]:
    """
    Prompt user whether to migrate a virtual interface.
    
    Returns:
        New device name, or None to skip
    """
    usage = ", ".join(info.used_by) if info.used_by else "(unused)"
    print(f"\n{device} (used by: {usage})", file=sys.stderr)
    
    print("  Migrate this interface? [y/N]: ", end="", file=sys.stderr)
    migrate = input().strip().lower()
    if migrate not in ("y", "yes"):
        return None
    
    while True:
        print(f"  New name [{device}]: ", end="", file=sys.stderr)
        new_name = input().strip()
        
        if not new_name or new_name == device:
            print("  Skipping (no change)", file=sys.stderr)
            return None
        
        return new_name


# =============================================================================
# Migration Logic
# =============================================================================

def build_migration_mappings(
    interfaces: dict[str, InterfaceInfo]
) -> list[MigrationMapping]:
    """
    Interactively build migration mappings from user input.
    
    Returns:
        List of MigrationMapping objects
    """
    mappings: list[MigrationMapping] = []
    physical_mappings: dict[str, str] = {}  # For VLAN auto-rename
    
    # Get interface lists
    physical = get_physical_interfaces(interfaces)
    virtual = get_virtual_interfaces(interfaces)
    vlans = get_vlan_interfaces(interfaces)
    
    # Summary
    print("\nDiscovered interfaces:", file=sys.stderr)
    if physical:
        print(f"  Physical: {', '.join(physical)}", file=sys.stderr)
    if virtual:
        print(f"  Virtual:  {', '.join(virtual)}", file=sys.stderr)
    if vlans:
        print(f"  VLANs:    {', '.join(vlans)}", file=sys.stderr)
    
    # Physical interface migration
    if physical:
        print("\n" + "=" * 50, file=sys.stderr)
        print("Physical Interface Migration", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        print("Enter new device name or press Enter to keep unchanged.", file=sys.stderr)
        
        for device in physical:
            new_name = prompt_device_migration(device, interfaces[device])
            if new_name:
                mappings.append(MigrationMapping(device, new_name))
                physical_mappings[device] = new_name
    
    # Virtual interface migration
    if virtual:
        print("\n" + "=" * 50, file=sys.stderr)
        print("Virtual Interface Migration", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        for device in virtual:
            new_name = prompt_virtual_migration(device, interfaces[device])
            if new_name:
                mappings.append(MigrationMapping(device, new_name))
    
    # Auto-generate VLAN mappings based on parent changes
    if vlans and physical_mappings:
        print("\n" + "=" * 50, file=sys.stderr)
        print("VLAN Interface Auto-Rename", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        for vlan_device in vlans:
            info = interfaces[vlan_device]
            if info.vlan_parent in physical_mappings:
                old_parent = info.vlan_parent
                new_parent = physical_mappings[old_parent]
                new_vlan_name = f"{new_parent}_vlan{info.vlan_tag}"
                
                print(f"  {vlan_device} -> {new_vlan_name}", file=sys.stderr)
                mappings.append(MigrationMapping(vlan_device, new_vlan_name, is_auto=True))
    
    return mappings


def apply_migrations(root: ET.Element, mappings: list[MigrationMapping]) -> dict[str, int]:
    """
    Apply migration mappings to the configuration.
    
    Updates:
    - <interfaces>/<*>/<if> - interface device assignments
    - <vlans>/<vlan>/<if> - VLAN parent interface
    - <vlans>/<vlan>/<vlanif> - VLAN interface name
    - <ppps>/<ppp>/<ports> - PPP port assignments
    
    Returns:
        Dict with counts of changes per section
    """
    # Build lookup dict for fast replacement
    replacements = {m.old_name: m.new_name for m in mappings}
    
    counts = {
        "interfaces": 0,
        "vlans_parent": 0,
        "vlans_vlanif": 0,
        "ppps": 0,
    }
    
    # Update <interfaces> section
    interfaces_elem = root.find("interfaces")
    if interfaces_elem is not None:
        for iface in interfaces_elem:
            if_elem = iface.find("if")
            if if_elem is not None and if_elem.text in replacements:
                if_elem.text = replacements[if_elem.text]
                counts["interfaces"] += 1
    
    # Update <vlans> section
    vlans_elem = root.find("vlans")
    if vlans_elem is not None:
        for vlan in vlans_elem.findall("vlan"):
            # Update parent interface
            if_elem = vlan.find("if")
            if if_elem is not None and if_elem.text in replacements:
                if_elem.text = replacements[if_elem.text]
                counts["vlans_parent"] += 1
            
            # Update vlanif name
            vlanif_elem = vlan.find("vlanif")
            if vlanif_elem is not None and vlanif_elem.text in replacements:
                vlanif_elem.text = replacements[vlanif_elem.text]
                counts["vlans_vlanif"] += 1
    
    # Update <ppps> section
    ppps_elem = root.find("ppps")
    if ppps_elem is not None:
        for ppp in ppps_elem.findall("ppp"):
            ports_elem = ppp.find("ports")
            if ports_elem is not None and ports_elem.text in replacements:
                ports_elem.text = replacements[ports_elem.text]
                counts["ppps"] += 1
    
    return counts


# =============================================================================
# Main
# =============================================================================

def print_usage():
    """Print usage information."""
    print("Usage: python3 migrate_interfaces.py <input_config.xml> [output_config.xml]", file=sys.stderr)
    print(file=sys.stderr)
    print("Migrate OPNsense interface device names to new hardware.", file=sys.stderr)
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
    
    # Header
    print("OPNsense Interface Migration Tool", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(f"Input:  {input_path}", file=sys.stderr)
    print(f"Output: {output_path if output_path else 'stdout'}", file=sys.stderr)
    
    # Load config
    tree, root = load_config(input_path)
    
    # Discover interfaces
    interfaces = discover_interfaces(root)
    
    if not interfaces:
        print("\nNo interfaces found in configuration!", file=sys.stderr)
        sys.exit(1)
    
    # Get migration mappings interactively
    mappings = build_migration_mappings(interfaces)
    
    if not mappings:
        print("\nNo migrations specified. Nothing to do.", file=sys.stderr)
        sys.exit(0)
    
    # Confirm
    print("\n" + "=" * 50, file=sys.stderr)
    print("Migration Summary", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    
    manual_mappings = [m for m in mappings if not m.is_auto]
    auto_mappings = [m for m in mappings if m.is_auto]
    
    if manual_mappings:
        print("\nManual mappings:", file=sys.stderr)
        for m in manual_mappings:
            print(f"  {m.old_name} -> {m.new_name}", file=sys.stderr)
    
    if auto_mappings:
        print("\nAuto-generated VLAN mappings:", file=sys.stderr)
        for m in auto_mappings:
            print(f"  {m.old_name} -> {m.new_name}", file=sys.stderr)
    
    print(file=sys.stderr)
    print("Apply these migrations? [Y/n]: ", end="", file=sys.stderr)
    confirm = input().strip().lower()
    if confirm and confirm not in ("y", "yes"):
        print("Aborted.", file=sys.stderr)
        sys.exit(0)
    
    # Apply migrations
    print("\nApplying migrations...", file=sys.stderr)
    counts = apply_migrations(root, mappings)
    
    # Report changes
    print("\nChanges applied:", file=sys.stderr)
    print(f"  Interface assignments: {counts['interfaces']}", file=sys.stderr)
    print(f"  VLAN parent interfaces: {counts['vlans_parent']}", file=sys.stderr)
    print(f"  VLAN interface names: {counts['vlans_vlanif']}", file=sys.stderr)
    print(f"  PPP ports: {counts['ppps']}", file=sys.stderr)
    
    total = sum(counts.values())
    print(f"  Total: {total} changes", file=sys.stderr)
    
    # Write output
    indent_xml(root)
    if output_path:
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        print(f"\nMigrated config written to: {output_path}", file=sys.stderr)
    else:
        tree.write(sys.stdout, encoding="unicode", xml_declaration=True)
        print(file=sys.stderr)  # newline after XML output
    
    print("\nNext steps:", file=sys.stderr)
    print("  1. Review the migrated config file", file=sys.stderr)
    print("  2. Import into OPNsense via System > Configuration > Backups", file=sys.stderr)
    print("  3. Reboot to apply the new interface assignments", file=sys.stderr)


if __name__ == "__main__":
    main()
