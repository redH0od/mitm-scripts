from scapy.all import ICMP, IP, sr1

def ping_host(target):
    ip = IP(dst=target)
    icmp = ICMP()
    response = sr1(ip/icmp, timeout=2, verbose=False)
    
    if response == None:
        print(f"Host {target} isn't available (timeout).")
    else:
        print(f"Host {target} is available.")

if __name__ == "__main__":
    target_host = input("IP: ")
    ping_host(target_host)
