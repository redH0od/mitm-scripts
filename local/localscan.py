from scapy.all import ARP, Ether, srp

def scan_network(network):
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    responce = srp(packet, timeout=3, verbose=False)[0]
    devices = []
  
    for sent, received in responce:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def display_devices(devices):
    print("IP Address\t\tMAC Address")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

network = input("Enter network to scan: ") #Указывайте диапазон в маске!
devices = scan_network(network)
display_devices(devices)
