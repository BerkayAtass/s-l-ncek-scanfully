#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Nmap XML to CSV Converter

This script converts Nmap XML output to CSV format, capturing all relevant information
including host details, port information, service details, OS detection, and script output.

Usage:
    python3 nmap_full_converter.py -i input.xml -o output.csv

Author: Claude
Date: 2025-03-22
"""

import xml.etree.ElementTree as ET
import csv
import argparse
import os
import sys
from datetime import datetime

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Convert Nmap XML output to comprehensive CSV format.')
    parser.add_argument('-i', '--input', required=True, help='Input Nmap XML file or directory containing XML files')
    parser.add_argument('-o', '--output', help='Output CSV file (default: output.csv)', default='output.csv')
    parser.add_argument('-d', '--delimiter', help='CSV delimiter (default: ";")', default=';')
    parser.add_argument('-s', '--skip-header', help='Skip CSV header', action='store_true')
    parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
    parser.add_argument('--separate-ports', help='Create separate row for each port', action='store_true')
    
    return parser.parse_args()

def print_banner():
    """Print a banner for the script."""
    print("=" * 70)
    print("Comprehensive Nmap XML to CSV Converter")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

def get_xml_files(input_path):
    """Get a list of XML files from the input path."""
    xml_files = []
    
    if os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for file in files:
                if file.endswith('.xml'):
                    xml_files.append(os.path.join(root, file))
    elif os.path.isfile(input_path):
        if input_path.endswith('.xml'):
            xml_files.append(input_path)
        else:
            print(f"Warning: {input_path} is not an XML file.")
    else:
        print(f"Error: {input_path} does not exist.")
        sys.exit(1)
    
    return xml_files

def extract_script_output(script_element):
    """Extract script output from a script element."""
    if script_element is None:
        return ""
        
    script_id = script_element.get('id', '')
    script_output = script_element.get('output', '')
    
    # Clean up the script output for CSV format
    script_output = script_output.replace('\n', '|').replace('\r', '')
    
    return f"{script_id}: {script_output}"

def combine_script_outputs(scripts):
    """Combine multiple script outputs into a single string."""
    if not scripts:
        return ""
        
    outputs = []
    for script in scripts:
        outputs.append(extract_script_output(script))
    
    return " || ".join(outputs)

def extract_host_information(host):
    """Extract host information from a host element."""
    host_info = {
        'ip_addr': '',
        'mac_addr': '',
        'mac_vendor': '',
        'hostname': '',
        'os': '',
        'accuracy': '',
        'status': '',
        'reason': '',
        'start_time': host.get('starttime', ''),
        'end_time': host.get('endtime', '')
    }
    
    # Get IP and MAC addresses
    for address in host.findall('./address'):
        addr_type = address.get('addrtype')
        if addr_type == 'ipv4' or addr_type == 'ipv6':
            host_info['ip_addr'] = address.get('addr', '')
        elif addr_type == 'mac':
            host_info['mac_addr'] = address.get('addr', '')
            host_info['mac_vendor'] = address.get('vendor', '')
    
    # Get hostname
    hostname_element = host.find('./hostnames/hostname')
    if hostname_element is not None:
        host_info['hostname'] = hostname_element.get('name', '')
    
    # Get status
    status_element = host.find('./status')
    if status_element is not None:
        host_info['status'] = status_element.get('state', '')
        host_info['reason'] = status_element.get('reason', '')
    
    # Get OS detection
    os_elements = host.findall('./os/osmatch')
    if os_elements:
        # Get the OS match with highest accuracy
        best_match = max(os_elements, key=lambda x: int(x.get('accuracy', '0')))
        host_info['os'] = best_match.get('name', '')
        host_info['accuracy'] = best_match.get('accuracy', '')
    
    return host_info

def extract_port_information(port):
    """Extract port information from a port element."""
    port_info = {
        'port_id': port.get('portid', ''),
        'protocol': port.get('protocol', ''),
        'state': '',
        'reason': '',
        'service_name': '',
        'service_product': '',
        'service_version': '',
        'service_extrainfo': '',
        'service_tunnel': '',
        'service_method': '',
        'service_conf': '',
        'script_output': ''
    }
    
    # Get state information
    state_element = port.find('./state')
    if state_element is not None:
        port_info['state'] = state_element.get('state', '')
        port_info['reason'] = state_element.get('reason', '')
    
    # Get service information
    service_element = port.find('./service')
    if service_element is not None:
        port_info['service_name'] = service_element.get('name', '')
        port_info['service_product'] = service_element.get('product', '')
        port_info['service_version'] = service_element.get('version', '')
        port_info['service_extrainfo'] = service_element.get('extrainfo', '')
        port_info['service_tunnel'] = service_element.get('tunnel', '')
        port_info['service_method'] = service_element.get('method', '')
        port_info['service_conf'] = service_element.get('conf', '')
    
    # Get script output
    scripts = port.findall('./script')
    port_info['script_output'] = combine_script_outputs(scripts)
    
    return port_info

def parse_xml_file(xml_file, args):
    """Parse an XML file and return a list of dictionaries with host and port information."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Get scan information
        scan_info = {
            'scanner': root.get('scanner', ''),
            'args': root.get('args', ''),
            'start': root.get('start', ''),
            'startstr': root.get('startstr', ''),
            'version': root.get('version', ''),
            'xmloutputversion': root.get('xmloutputversion', '')
        }
        
        # Store all parsed data
        parsed_data = []
        
        # Process each host
        for host in root.findall('./host'):
            host_info = extract_host_information(host)
            
            # Process each port for this host
            ports = host.findall('./ports/port')
            
            if args.separate_ports:
                # Create a separate row for each port
                for port in ports:
                    port_info = extract_port_information(port)
                    
                    # Combine host and port information
                    row = {**scan_info, **host_info, **port_info}
                    parsed_data.append(row)
                
                # If no ports, still include the host
                if not ports:
                    row = {**scan_info, **host_info}
                    parsed_data.append(row)
            else:
                # Combine all ports into a single row
                all_ports = []
                all_services = []
                all_scripts = []
                
                for port in ports:
                    port_info = extract_port_information(port)
                    port_str = f"{port_info['port_id']}/{port_info['protocol']}"
                    service_str = f"{port_info['service_name']} {port_info['service_product']} {port_info['service_version']}".strip()
                    
                    all_ports.append(port_str)
                    all_services.append(service_str)
                    
                    if port_info['script_output']:
                        all_scripts.append(f"{port_str}: {port_info['script_output']}")
                
                # Combine host and port information
                row = {
                    **scan_info,
                    **host_info,
                    'ports': ', '.join(all_ports),
                    'services': ', '.join(all_services),
                    'script_output': ' || '.join(all_scripts)
                }
                
                parsed_data.append(row)
                
        return parsed_data
        
    except ET.ParseError as e:
        print(f"Error parsing XML file {xml_file}: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error processing {xml_file}: {e}")
        return []

def write_to_csv(data, output_file, delimiter=';', skip_header=False):
    """Write the parsed data to a CSV file."""
    if not data:
        print("No data to write to CSV.")
        return False
    
    # Get all possible field names from all dictionaries
    fieldnames = set()
    for item in data:
        fieldnames.update(item.keys())
    
    # Convert to list and sort for consistent output
    fieldnames = sorted(list(fieldnames))
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=delimiter, 
                                   quoting=csv.QUOTE_ALL)
            
            if not skip_header:
                writer.writeheader()
            
            writer.writerows(data)
        
        return True
    except Exception as e:
        print(f"Error writing to CSV file: {e}")
        return False

def main():
    """Main function."""
    args = parse_args()
    print_banner()
    
    xml_files = get_xml_files(args.input)
    
    if not xml_files:
        print("No XML files found.")
        sys.exit(1)
    
    print(f"Found {len(xml_files)} XML file(s) to process.")
    
    all_data = []
    
    for xml_file in xml_files:
        if args.verbose:
            print(f"Processing {xml_file}...")
        
        parsed_data = parse_xml_file(xml_file, args)
        all_data.extend(parsed_data)
        
        if args.verbose:
            print(f"  - Found {len(parsed_data)} entries.")
    
    if all_data:
        success = write_to_csv(all_data, args.output, args.delimiter, args.skip_header)
        
        if success:
            print(f"Successfully wrote {len(all_data)} entries to {args.output}")
        else:
            print(f"Failed to write to {args.output}")
    else:
        print("No data was parsed from the XML file(s).")
    
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
