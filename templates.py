from scapy.all import *
import random

VALID_PROTOCOLS = ["IP", "TCP", "UDP", "ICMP", "ARP"]

CACHED_DATA = {
    "protocols": [],
    "interface": "",
    "source_mac": "",
    "destination_mac": "",
    "source_ip": get_if_addr(conf.iface),
    "destination_ip":"127.0.0.1",
    "source_port": random.randint(1024, 65535),
    "destination_port": 80,
    "sequence_number" : None,
    "acknowledge_number" : None,
}
