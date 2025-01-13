import os
from scapy.all import ARP, Ether, srp
import socket

def scan_network_and_probe(ip_range):
    devices = []
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    try:
        answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)
    except PermissionError:
        print("Permission denied. Please run this script with elevated privileges (e.g., 'sudo').")
        exit(1)

    for sent, received in answered:
        device_info = {'ip': received.psrc, 'mac': received.hwsrc}

        # Try to get hostname
        try:
            device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
        except (socket.herror, socket.gaierror, socket.timeout) as e:
            device_info['hostname'] = "Unknown"
            print(f"Hostname lookup failed for {received.psrc}: {e}")

        # Try to scan ports
        try:
            device_info['open_ports'] = scan_ports(received.psrc)
        except Exception as e:
            device_info['open_ports'] = []
            print(f"Port scanning failed for {received.psrc}: {e}")

        devices.append(device_info)

    return devices

def scan_ports(ip):
    open_ports = []
    for port in range(20, 1025):  # Scan common ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

if __name__ == "__main__":
    network_range = "192.168.1.1/24"
    print(f"Scanning network: {network_range}...\n")
    devices = scan_network_and_probe(network_range)
    
    print("IP Address\tMAC Address\t\tHostname\t\tOpen Ports")
    print("-" * 80)
    for device in devices:
        open_ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "None"
        print(f"{device['ip']}\t{device['mac']}\t{device['hostname']}\t{open_ports_str}")
