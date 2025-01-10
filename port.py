import os
from scapy.all import ARP, Ether, srp
import socket

def scan_network_and_probe(ip_range):
    devices = []
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    for sent, received in answered:
        device_info = {'ip': received.psrc, 'mac': received.hwsrc}
        try:
            # Probe device for open ports and hostnames
            device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
            device_info['open_ports'] = scan_ports(received.psrc)
        except Exception:
            device_info['hostname'] = "Unknown"
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
        print(f"{device['ip']}\t{device['mac']}\t{device['hostname']}\t{device['open_ports']}")
