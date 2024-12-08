#!/usr/bin/env python3

"""
Network Scanner Tool - Version 2.0
Developed by Parmar Sahil

Description:
This tool allows you to perform:
1. ARP scanning to discover devices in a network.
2. TCP scanning to identify open ports on a specific host.

Usage:
    python3 network_scanner.py ARP <IP or Range>
    python3 network_scanner.py TCP <IP> <ports...> [--range]

"""

import argparse
from scapy.all import Ether, ARP, srp, IP, TCP, sr

# ARP scan to discover devices in the network
def perform_arp_scan(target_ip):
    """
    Perform ARP-based network scanning.

    Args:
        target_ip (str): Target IP or range (e.g., 192.168.1.1 or 192.168.1.1/24).

    Returns:
        list: A list of dictionaries with 'IP' and 'MAC' mappings of discovered devices.
    """
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered, unanswered = srp(arp_request, timeout=2, retry=2, verbose=0)
    
    devices = []
    for sent_packet, received_packet in answered:
        devices.append({'IP': received_packet.psrc, 'MAC': received_packet.hwsrc})

    return devices

# TCP scan to identify open ports on a target
def perform_tcp_scan(target_host, port_list):
    """
    Perform TCP port scanning using SYN packets.

    Args:
        target_host (str): Target IP or hostname.
        port_list (list): List of ports to scan.

    Returns:
        list: A list of open ports.
    """
    try:
        syn_packets = IP(dst=target_host) / TCP(dport=port_list, flags="S")
    except Exception as e:
        raise ValueError(f"Error resolving hostname {target_host}: {e}")

    answered, unanswered = sr(syn_packets, timeout=2, retry=2, verbose=0)

    open_ports = []
    for sent_packet, received_packet in answered:
        if received_packet[TCP].flags == "SA":
            open_ports.append(received_packet[TCP].sport)

    return open_ports

# Command-line interface setup
def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    subparsers = parser.add_subparsers(dest="action", required=True, help="Action to perform.")

    # Subparser for ARP scanning
    arp_parser = subparsers.add_parser("ARP", help="Perform ARP-based network scanning.")
    arp_parser.add_argument("target", help="Target IP or range (e.g., 192.168.1.1/24).")

    # Subparser for TCP scanning
    tcp_parser = subparsers.add_parser("TCP", help="Perform TCP port scanning.")
    tcp_parser.add_argument("host", help="Target IP or hostname.")
    tcp_parser.add_argument("ports", nargs="+", type=int, help="List of ports to scan (e.g., 22 80 443).")
    tcp_parser.add_argument("--range", action="store_true", help="Specify a range of ports.")

    args = parser.parse_args()

    # Execute ARP scan
    if args.action == "ARP":
        results = perform_arp_scan(args.target)
        if results:
            print("Discovered Devices:")
            for device in results:
                print(f"IP: {device['IP']}, MAC: {device['MAC']}")
        else:
            print("No devices found.")

    # Execute TCP scan
    elif args.action == "TCP":
        if args.range and len(args.ports) == 2:
            ports_to_scan = list(range(args.ports[0], args.ports[1] + 1))
        else:
            ports_to_scan = args.ports

        try:
            open_ports = perform_tcp_scan(args.host, ports_to_scan)
        except ValueError as err:
            print(err)
            exit(1)

        if open_ports:
            print("Open Ports:")
            for port in open_ports:
                print(f"Port {port} is open.")
        else:
            print("No open ports found.")

if __name__ == "__main__":
    main()
