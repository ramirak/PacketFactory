from scapy.all import *
from templates import *
from validations import *
import random

def prepare_packet(profile_data, pkt):
    l2, l3, l4, l5 = None, None, None, None

    # START LAYER 2

    source, destination = 0, 0
    if "source_mac" in pkt: 
        if not is_valid_mac(pkt["source_mac"]):
            print("Invalid source mac address.")
            return -1
        source = 1

    if "destination_mac" in pkt: 
        if not is_valid_mac(pkt["destination_mac"]):
            print("Invalid destination mac address.")
            return -1
        destination = 1

    l2 = build_l2(pkt, source, destination)

    # END LAYER 2
    # START LAYER 3

    source, destination = 0, 0
    if "source_ip" in pkt: 
        if not is_valid_IPv4(pkt["source_ip"]):
            print("Invalid source ip address.")
            return -1
        source = 1

    if "destination_ip" in pkt:
        if not is_valid_IPv4(pkt["destination_ip"]):
            print("Invalid destination ip address.")
            return -1
        destination = 1

    l3 = build_l3(profile_data, pkt ,source, destination)

    # END LAYER 3
    # START LAYER 4

    source, destination = 0, 0
    if "source_port" in pkt: 
        if not is_valid_port(pkt["source_port"]):
            print("Invalid source port.")
            return -1
        source = 1

    if "destination_port" in pkt: 
        if not is_valid_port(pkt["destination_port"]):
            print("Invalid destination port.")
            return -1
        destination = 1

    l4 = build_l4(profile_data, pkt, source, destination)

    # END LAYER 4
    
    if "payload" in pkt:
        l5 = build_l5(profile_data, pkt)
    
    return combine_layers(l2, l3, l4, l5)


def build_l2(pkt, source, destination):
    l2 = None

    ether_args = {}
    
    # Override cached data
    if source: CACHED_DATA["source_mac"] = pkt["source_mac"]
    if CACHED_DATA["source_mac"] != "": ether_args.add("src", CACHED_DATA["source_mac"])

    # Override cached data
    if destination: CACHED_DATA["destination_mac"] = pkt["destination_mac"]
    if CACHED_DATA["destination_mac"] != "": ether_args.add("dst", CACHED_DATA["destination_mac"])

    if len(ether_args) == 0:
        return None

    l2 = Ether(**ether_args)
    
    return l2


def build_l3(profile_data, pkt, source, destination):
    l3 = None
    wrapper = IP
    if "ARP" in profile_data["protocol"]: 
        wrapper = ARP

    # Override cached / default data
    if source: 
        CACHED_DATA["source_ip"] = pkt["source_ip"]
    if destination: 
        CACHED_DATA["destination_ip"] = pkt["destination_ip"]

    return wrapper(src=CACHED_DATA["source_ip"], dst=CACHED_DATA["destination_ip"])


def build_l4(profile_data, pkt, source, destination): 
    args = {}
    wrapper = TCP
    proto = "TCP"
    if "UDP" in profile_data["protocol"]:
        wrapper = UDP
        proto = "UDP"

    flags = pkt["flags"]
    tcp_flags_short = str()
    if "tcp_flags" in flags:
        tcp_flags = flags["tcp_flags"]
        for flag in tcp_flags:
            tcp_flags_short += flag[0].upper()
        args.update({"flags": tcp_flags_short})

    if proto == "TCP":    
        seq_num, ack_num = -1, -1
        if "sequence_number" in pkt:
            seq_num = pkt["sequence_number"]
        elif CACHED_DATA["sequence_number"] != None:
            seq_num = CACHED_DATA["sequence_number"]
        else:
            seq_num = 1000

        if "acknowledge_number" in pkt:
            ack_num = pkt["acknowledge_number"]
        elif CACHED_DATA["acknowledge_number"] != None:
            ack_num = CACHED_DATA["acknowledge_number"]
        
        if seq_num != -1: args.update({"seq": seq_num})
        if ack_num != -1: args.update({"ack": ack_num})

        # Override cached data
        if source: 
            CACHED_DATA["source_port"] = pkt["source_port"]
        # Override cached data
        if destination: 
            CACHED_DATA["destination_port"] = pkt["destination_port"]

    return wrapper(sport=CACHED_DATA["source_port"], dport=CACHED_DATA["destination_port"], **args)

     
def build_l5(profile_data, pkt):
    get_request = "GET /test.php HTTP/1.1\r\nHost: " + str(CACHED_DATA["destination_ip"]) + "\r\n\r\n"
    return get_request


def combine_layers(l2, l3, l4, l5):
    if l2 is not None and l3 is not None and l4 is not None and l5 is not None:
        return l2/l3/l4/l5
    if l2 is not None and l3 is not None and l4 is not None:
        return l2/l3/l4        
    if l2 is not None and l3 is not None:
        return l2/l3
    if l3 is not None and l4 is not None and l5 is not None:
        return l3/l4/l5
    if l3 is not None and l4 is not None:
        return l3/l4
    return None


def send_packet(packet, no_wait, is_tcp):
    print("Sending packet: " + CACHED_DATA["source_ip"] + " : " + str(CACHED_DATA["source_port"]) + " -> " + CACHED_DATA["destination_ip"] + " : " + str(CACHED_DATA["destination_port"]))
    if(no_wait):
        send(packet, verbose=False)
      #  TCP_PUSH=TCP(sport=CACHED_DATA["source_port"], dport=CACHED_DATA["destination_port"], flags="PA", seq=CACHED_DATA["sequence_number"], ack=CACHED_DATA["acknowledge_number"])
      #  send(IP(src=CACHED_DATA["source_ip"], dst=CACHED_DATA["destination_ip"])/TCP_PUSH/"test")
        return
    res = sr1(packet, timeout=2, verbose=False)
    if is_tcp and res != None:
        CACHED_DATA["sequence_number"] = res.ack
        CACHED_DATA["acknowledge_number"] = res.seq + 1
    if res == None:
        print("** Got no response **")
        return False
    return True


