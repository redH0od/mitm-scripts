from scapy.all import ARP, Ether, srp
import socket

def scan_network(network):
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    responce = srp(packet, timeout=3, verbose=False)[0]
    devices = []
  
    for sent, received in responce:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        try:
            device_info['hostname'] = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            device_info['hostname'] = "Unknown"
        
        devices.append(device_info)

    return devices

def display_devices(devices):
    print("IP Address\t\tMAC Address\t\tHostname")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t{device['hostname']}")

network = input("Enter network to scan: ") #Указывайте диапазон в маске (в конце /24 просто добавляйте)!
devices = scan_network(network)
display_devices(devices)
