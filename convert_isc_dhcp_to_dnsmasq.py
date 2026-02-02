#!/usr/bin/env python3
"""
Convert OPNsense ISC DHCP configuration to Dnsmasq DHCP.

This script reads an exported OPNsense config.xml file containing ISC DHCP
settings and produces a new config.xml with the DHCP configuration migrated
to Dnsmasq format (the default DHCP server in OPNsense 26.1+).

Features:
- Converts DHCP ranges per interface
- Converts static IP reservations (staticmap)
- Converts common DHCP options (DNS, NTP, domain, WINS)
- Removes legacy ISC DHCP configuration
- Removes os-isc-dhcp plugin reference

Usage:
    python3 convert_isc_dhcp_to_dnsmasq.py <input_config.xml> [output_config.xml]

If output_config.xml is not specified, the migrated config is written to stdout.

Author: Generated for OPNsense 26.1 migration
"""

import copy
import ipaddress
import sys
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DhcpRange:
    """Represents a DHCP range."""
    interface: str
    start_addr: str
    end_addr: str
    domain: str = ""
    lease_time: str = ""
    description: str = ""


@dataclass
class DhcpHost:
    """Represents a static DHCP reservation."""
    hostname: str
    mac: str
    ip: str
    descr: str = ""
    interface: str = ""  # For tracking/reporting only


@dataclass
class DhcpOption:
    """Represents a DHCP option."""
    interface: str
    option_num: str  # e.g., "6" for DNS, "15" for domain, "42" for NTP, "44" for WINS
    value: str
    description: str = ""


@dataclass
class MigrationReport:
    """Collects migration statistics and warnings."""
    ranges_added: dict = field(default_factory=dict)
    hosts_added: dict = field(default_factory=dict)
    options_added: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    skipped_interfaces: list = field(default_factory=list)
    
    def summary(self) -> str:
        lines = ["Migration Summary", "=" * 50]
        
        total_ranges = sum(self.ranges_added.values())
        total_hosts = sum(self.hosts_added.values())
        total_options = sum(self.options_added.values())
        
        lines.append(f"DHCP Ranges migrated: {total_ranges}")
        for iface, count in self.ranges_added.items():
            lines.append(f"  - {iface}: {count} range(s)")
        
        lines.append(f"Static reservations migrated: {total_hosts}")
        for iface, count in self.hosts_added.items():
            lines.append(f"  - {iface}: {count} host(s)")
        
        lines.append(f"DHCP options migrated: {total_options}")
        for iface, count in self.options_added.items():
            lines.append(f"  - {iface}: {count} option(s)")
        
        if self.skipped_interfaces:
            lines.append(f"Skipped interfaces (disabled): {', '.join(self.skipped_interfaces)}")
        
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ! {w}")
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        return {
            "ranges_added": self.ranges_added,
            "hosts_added": self.hosts_added,
            "options_added": self.options_added,
            "warnings": self.warnings,
            "skipped_interfaces": self.skipped_interfaces,
        }


def get_text(element: Optional[ET.Element], default: str = "") -> str:
    """Safely get text content from an XML element."""
    if element is None:
        return default
    return element.text or default


def generate_uuid() -> str:
    """Generate a UUID for new dnsmasq entries."""
    return str(uuid.uuid4())


def parse_isc_dhcp(root: ET.Element, include_disabled: bool = False) -> tuple[list[DhcpRange], list[DhcpHost], list[DhcpOption], MigrationReport]:
    """
    Parse ISC DHCP configuration from config.xml.
    
    Returns:
        Tuple of (ranges, hosts, options, report)
    """
    report = MigrationReport()
    ranges = []
    hosts = []
    options = []
    seen_macs = {}  # Track MAC addresses to detect duplicates
    
    dhcpd = root.find("dhcpd")
    if dhcpd is None:
        report.warnings.append("No <dhcpd> section found in config")
        return ranges, hosts, options, report
    
    for iface_elem in dhcpd:
        iface_name = iface_elem.tag
        
        # Check if interface DHCP is enabled
        enable = get_text(iface_elem.find("enable"))
        if enable != "1" and not include_disabled:
            report.skipped_interfaces.append(iface_name)
            continue
        
        # Parse DHCP range
        range_elem = iface_elem.find("range")
        if range_elem is not None:
            from_addr = get_text(range_elem.find("from"))
            to_addr = get_text(range_elem.find("to"))
            if from_addr and to_addr:
                domain = get_text(iface_elem.find("domain"))
                ranges.append(DhcpRange(
                    interface=iface_name,
                    start_addr=from_addr,
                    end_addr=to_addr,
                    domain=domain,
                ))
                report.ranges_added[iface_name] = report.ranges_added.get(iface_name, 0) + 1
        
        # Parse static mappings
        for staticmap in iface_elem.findall("staticmap"):
            mac = get_text(staticmap.find("mac")).lower()
            ipaddr = get_text(staticmap.find("ipaddr"))
            hostname = get_text(staticmap.find("hostname"))
            descr = get_text(staticmap.find("descr"))
            
            if not mac or not ipaddr:
                if hostname:
                    report.warnings.append(f"Skipping staticmap '{hostname}': missing MAC or IP")
                continue
            
            # Check for duplicate MACs
            if mac in seen_macs:
                existing = seen_macs[mac]
                if existing.ip != ipaddr:
                    report.warnings.append(
                        f"Duplicate MAC {mac}: '{hostname}' ({ipaddr}) vs '{existing.hostname}' ({existing.ip}) - keeping first"
                    )
                continue
            
            host = DhcpHost(
                hostname=hostname,
                mac=mac,
                ip=ipaddr,
                descr=descr,
                interface=iface_name,
            )
            hosts.append(host)
            seen_macs[mac] = host
            report.hosts_added[iface_name] = report.hosts_added.get(iface_name, 0) + 1
        
        # Parse DHCP options
        # DNS servers (option 6)
        for dns_elem in iface_elem.findall("dnsserver"):
            dns_server = get_text(dns_elem)
            if dns_server:
                options.append(DhcpOption(
                    interface=iface_name,
                    option_num="6",
                    value=dns_server,
                    description=f"DNS server for {iface_name}",
                ))
                report.options_added[iface_name] = report.options_added.get(iface_name, 0) + 1
        
        # Domain (option 15)
        domain = get_text(iface_elem.find("domain"))
        if domain:
            options.append(DhcpOption(
                interface=iface_name,
                option_num="15",
                value=domain,
                description=f"Domain for {iface_name}",
            ))
            report.options_added[iface_name] = report.options_added.get(iface_name, 0) + 1
        
        # NTP server (option 42)
        ntp_server = get_text(iface_elem.find("ntpserver"))
        if ntp_server:
            options.append(DhcpOption(
                interface=iface_name,
                option_num="42",
                value=ntp_server,
                description=f"NTP server for {iface_name}",
            ))
            report.options_added[iface_name] = report.options_added.get(iface_name, 0) + 1
        
        # WINS server (option 44)
        wins_server = get_text(iface_elem.find("winsserver"))
        if wins_server:
            options.append(DhcpOption(
                interface=iface_name,
                option_num="44",
                value=wins_server,
                description=f"WINS server for {iface_name}",
            ))
            report.options_added[iface_name] = report.options_added.get(iface_name, 0) + 1
    
    return ranges, hosts, options, report


def create_dnsmasq_range_element(dhcp_range: DhcpRange) -> ET.Element:
    """Create a dnsmasq dhcp_ranges XML element."""
    elem = ET.Element("dhcp_ranges")
    elem.set("uuid", generate_uuid())
    
    # Required fields
    ET.SubElement(elem, "interface").text = dhcp_range.interface
    ET.SubElement(elem, "start_addr").text = dhcp_range.start_addr
    ET.SubElement(elem, "end_addr").text = dhcp_range.end_addr
    
    # Optional fields with defaults
    ET.SubElement(elem, "set_tag")
    ET.SubElement(elem, "subnet_mask")
    ET.SubElement(elem, "constructor")
    ET.SubElement(elem, "mode")
    ET.SubElement(elem, "prefix_len")
    ET.SubElement(elem, "lease_time").text = dhcp_range.lease_time
    ET.SubElement(elem, "domain_type").text = "range"
    ET.SubElement(elem, "domain").text = dhcp_range.domain
    ET.SubElement(elem, "nosync").text = "0"
    ET.SubElement(elem, "ra_mode")
    ET.SubElement(elem, "ra_priority")
    ET.SubElement(elem, "ra_mtu")
    ET.SubElement(elem, "ra_interval")
    ET.SubElement(elem, "ra_router_lifetime")
    ET.SubElement(elem, "description").text = dhcp_range.description
    
    return elem


def create_dnsmasq_host_element(host: DhcpHost) -> ET.Element:
    """Create a dnsmasq hosts XML element."""
    elem = ET.Element("hosts")
    elem.set("uuid", generate_uuid())
    
    ET.SubElement(elem, "host").text = host.hostname
    ET.SubElement(elem, "domain")
    ET.SubElement(elem, "local").text = "0"
    ET.SubElement(elem, "ip").text = host.ip
    ET.SubElement(elem, "cnames")
    ET.SubElement(elem, "client_id")
    ET.SubElement(elem, "hwaddr").text = host.mac
    ET.SubElement(elem, "lease_time")
    ET.SubElement(elem, "ignore").text = "0"
    ET.SubElement(elem, "set_tag")
    ET.SubElement(elem, "descr").text = host.descr
    ET.SubElement(elem, "comments")
    ET.SubElement(elem, "aliases")
    
    return elem


def create_dnsmasq_option_element(option: DhcpOption) -> ET.Element:
    """Create a dnsmasq dhcp_options XML element."""
    elem = ET.Element("dhcp_options")
    elem.set("uuid", generate_uuid())
    
    ET.SubElement(elem, "type").text = "set"
    ET.SubElement(elem, "option").text = option.option_num
    ET.SubElement(elem, "option6")
    ET.SubElement(elem, "interface").text = option.interface
    ET.SubElement(elem, "tag")
    ET.SubElement(elem, "set_tag")
    ET.SubElement(elem, "value").text = option.value
    ET.SubElement(elem, "force").text = "0"
    ET.SubElement(elem, "description").text = option.description
    
    return elem


def update_dnsmasq_config(
    root: ET.Element,
    ranges: list[DhcpRange],
    hosts: list[DhcpHost],
    options: list[DhcpOption],
    replace_existing: bool = False,
) -> None:
    """
    Update the dnsmasq section with migrated DHCP configuration.
    """
    # Find or create dnsmasq section
    dnsmasq = root.find("dnsmasq")
    if dnsmasq is None:
        dnsmasq = ET.SubElement(root, "dnsmasq")
        dnsmasq.set("version", "1.0.8")
        dnsmasq.set("description", "Dnsmasq DNS and DHCP")
    
    # Enable dnsmasq
    enable_elem = dnsmasq.find("enable")
    if enable_elem is None:
        enable_elem = ET.SubElement(dnsmasq, "enable")
    enable_elem.text = "1"
    
    # Set interfaces
    interfaces = sorted(set(r.interface for r in ranges))
    interface_elem = dnsmasq.find("interface")
    if interface_elem is None:
        interface_elem = ET.SubElement(dnsmasq, "interface")
    interface_elem.text = ",".join(interfaces)
    
    # Ensure dhcp section exists and is configured
    dhcp_section = dnsmasq.find("dhcp")
    if dhcp_section is None:
        dhcp_section = ET.SubElement(dnsmasq, "dhcp")
    
    # Settings that should always be set to ensure DHCP works correctly
    # These are critical for DHCP functionality and override any existing values
    dhcp_required = {
        "authoritative": "1",      # Required for DHCP to respond to new clients
        "default_fw_rules": "1",   # Required for DHCP traffic to be allowed
    }
    for key, value in dhcp_required.items():
        elem = dhcp_section.find(key)
        if elem is None:
            elem = ET.SubElement(dhcp_section, key)
        elem.text = value
    
    # Set default dhcp settings if not present (preserves existing values)
    dhcp_defaults = {
        "no_interface": "",
        "fqdn": "1",
        "domain": "",
        "local": "1",
        "lease_max": "",
        "reply_delay": "",
        "enable_ra": "0",
        "nosync": "0",
        "log_dhcp": "0",
        "log_quiet": "0",
    }
    for key, default_value in dhcp_defaults.items():
        elem = dhcp_section.find(key)
        if elem is None:
            elem = ET.SubElement(dhcp_section, key)
            elem.text = default_value
    
    # Remove existing entries if requested
    if replace_existing:
        for tag in ["dhcp_ranges", "hosts", "dhcp_options", "dhcp_tags", "dhcp_boot"]:
            for elem in dnsmasq.findall(tag):
                dnsmasq.remove(elem)
    
    # Add DHCP ranges
    for dhcp_range in ranges:
        dnsmasq.append(create_dnsmasq_range_element(dhcp_range))
    
    # Add hosts (static reservations)
    for host in hosts:
        dnsmasq.append(create_dnsmasq_host_element(host))
    
    # Add DHCP options
    for option in options:
        dnsmasq.append(create_dnsmasq_option_element(option))


def remove_isc_dhcp(root: ET.Element) -> bool:
    """
    Remove the ISC DHCP configuration from config.xml.
    
    Returns True if dhcpd was found and removed.
    """
    dhcpd = root.find("dhcpd")
    if dhcpd is not None:
        root.remove(dhcpd)
        return True
    return False


def remove_isc_dhcpv6(root: ET.Element) -> bool:
    """
    Remove the ISC DHCPv6 configuration from config.xml.
    
    Returns True if dhcpdv6 was found and removed.
    """
    dhcpdv6 = root.find("dhcpdv6")
    if dhcpdv6 is not None:
        root.remove(dhcpdv6)
        return True
    return False


def remove_isc_plugin(root: ET.Element) -> bool:
    """
    Remove os-isc-dhcp from the plugins list.
    
    Returns True if the plugin was found and removed.
    """
    firmware = root.find(".//system/firmware")
    if firmware is None:
        return False
    
    plugins = firmware.find("plugins")
    if plugins is None or not plugins.text:
        return False
    
    plugin_list = [p.strip() for p in plugins.text.split(",")]
    if "os-isc-dhcp" in plugin_list:
        plugin_list.remove("os-isc-dhcp")
        plugins.text = ",".join(plugin_list)
        return True
    
    return False


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


def print_usage():
    """Print usage information."""
    print("Usage: python3 convert_isc_dhcp_to_dnsmasq.py <input_config.xml> [output_config.xml]", file=sys.stderr)
    print(file=sys.stderr)
    print("Convert OPNsense ISC DHCP configuration to Dnsmasq DHCP.", file=sys.stderr)
    print(file=sys.stderr)
    print("Arguments:", file=sys.stderr)
    print("  input_config.xml   Path to the OPNsense configuration file", file=sys.stderr)
    print("  output_config.xml  Output file path (default: stdout)", file=sys.stderr)


def prompt_yes_no(message: str, default: bool = False) -> bool:
    """
    Prompt for a yes/no answer.
    
    Returns:
        True for yes, False for no
    """
    default_str = "Y/n" if default else "y/N"
    print(f"{message} [{default_str}]: ", end="", file=sys.stderr)
    answer = input().strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def main():
    # Parse arguments
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_usage()
        sys.exit(0 if len(sys.argv) > 1 else 1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else None

    print("OPNsense ISC DHCP to Dnsmasq Migration Tool", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(f"Input:  {input_path}", file=sys.stderr)
    print(f"Output: {output_path if output_path else 'stdout'}", file=sys.stderr)

    # Validate input file
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Parse input XML
    try:
        tree = ET.parse(input_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    if root.tag != "opnsense":
        print(f"Error: Root element is '{root.tag}', expected 'opnsense'", file=sys.stderr)
        sys.exit(1)

    # Interactive prompts for options
    print(file=sys.stderr)
    include_disabled = prompt_yes_no("Include disabled DHCP interfaces?", default=False)
    replace_dnsmasq = prompt_yes_no("Replace existing Dnsmasq DHCP config (instead of merging)?", default=False)
    keep_isc = prompt_yes_no("Keep ISC DHCP configuration (disable instead of remove)?", default=False)
    keep_isc_plugin = prompt_yes_no("Keep os-isc-dhcp in the plugins list?", default=False)

    # Parse ISC DHCP configuration
    ranges, hosts, options, report = parse_isc_dhcp(root, include_disabled)

    if not ranges and not hosts:
        print("Warning: No DHCP ranges or static mappings found to migrate", file=sys.stderr)

    # Print summary
    print(file=sys.stderr)
    print(report.summary(), file=sys.stderr)
    print(file=sys.stderr)

    # Confirm
    if not prompt_yes_no("Proceed with migration?", default=True):
        print("Aborted.", file=sys.stderr)
        sys.exit(0)

    # Update dnsmasq configuration
    update_dnsmasq_config(root, ranges, hosts, options, replace_dnsmasq)

    # Handle ISC DHCP removal
    if not keep_isc:
        if remove_isc_dhcp(root):
            print("Removed <dhcpd> section", file=sys.stderr)
        if remove_isc_dhcpv6(root):
            print("Removed <dhcpdv6> section", file=sys.stderr)
    else:
        # Disable ISC DHCP instead of removing
        dhcpd = root.find("dhcpd")
        if dhcpd is not None:
            for iface_elem in dhcpd:
                enable = iface_elem.find("enable")
                if enable is not None:
                    enable.text = "0"
            print("Disabled ISC DHCP (kept in config)", file=sys.stderr)

    # Handle ISC plugin removal
    if not keep_isc_plugin:
        if remove_isc_plugin(root):
            print("Removed os-isc-dhcp from plugins list", file=sys.stderr)

    # Pretty print XML
    indent_xml(root)

    # Write output
    if output_path:
        tree.write(output_path, encoding="unicode", xml_declaration=True)
        print(f"\nOutput written to {output_path}", file=sys.stderr)
    else:
        tree.write(sys.stdout, encoding="unicode", xml_declaration=True)
        print(file=sys.stderr)  # newline after XML output


if __name__ == "__main__":
    main()
