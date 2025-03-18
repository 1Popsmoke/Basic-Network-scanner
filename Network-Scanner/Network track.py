
print("Hello, Welcome to find IP!")
import scapy.all as scapy
import socket

def get_ip_range(network):
    # Calculate the network range from the given IP
    network_parts = network.split('.')
    base_ip = '.'.join(network_parts[:3]) + '.'
    return [base_ip + str(i) for i in range(1, 255)]

def scan_ip(ip):
    # Send a ARP request to detect if the device is up
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # If the device responds, return IP and MAC address
    if answered_list:
        ip_address = answered_list[0][1].psrc
        mac_address = answered_list[0][1].hwsrc
        try:
            # Resolve hostname from IP
            host_name = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            host_name = "Unknown"
        return {'IP': ip_address, 'MAC': mac_address, 'Host': host_name}
    return None

def scan_network(network):
    devices = []
    ip_range = get_ip_range(network)
    
    for ip in ip_range:
        device = scan_ip(ip)
        if device:
            devices.append(device)
    
    return devices

def display_results(devices):
    print("IP Address\t\tMAC Address\t\tHost Name")
    print("-" * 50)
    for device in devices:
        print(f"{device['IP']}\t\t{device['MAC']}\t\t{device['Host']}")

if __name__ == "__main__":
    network = input("Enter the network (e.g., 192.168.1.0/24): ").split('/')[0]
    print("Scanning the network, please wait...")
    devices = scan_network(network)
    display_results(devices)

