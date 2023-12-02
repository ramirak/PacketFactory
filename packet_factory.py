
import json, sys, argparse, os
from packet import *

LOGO = '''
   ___           __       __  ____         __               
  / _ \\___ _____/ /_____ / /_/ __/__ _____/ /____  ______ __
 / ___/ _ `/ __/  '_/ -_) __/ _// _ `/ __/ __/ _ \\/ __/ // /
/_/   \\_,_/\\__/_/\\_\\\\__/\\__/_/  \\_,_/\\__/\\__/\\___/_/  \\_, / 
                                                     /___/  

'''

def main():
    print(LOGO)
    chosen_profile = None

    data = get_all_data()
    if data is None:
        print("Failed to get data. Exiting.")
        return -1

    parser = argparse.ArgumentParser(description="PacketFactory - Create and inject custom packets easily.")
    parser.add_argument("-r", "--read", help = "Profile name", required = False, default = "")
    parser.add_argument("-d", "--drop", help = "Block RST/FIN packets", required = False, action='store_true')

    argument = parser.parse_args()

    if argument.drop:
        drop_packets()

    if argument.read != "":
        chosen_profile = argument.read
    else:
        print("No profile supplied. ")
        print("Optional profiles - ")
        for profile_name in data:
            print("- " + str(profile_name))
        return

    profile_data = prepare_profile(data, chosen_profile)
    
    if profile_data is None:
        print("Failed to prepare profile data. Exiting.")
        return -1

    i = 0 
    loop = 1 
    # Check if user defined retrasnmit number.
    if "additional_params" in profile_data:
        if "retransmit" in profile_data["additional_params"]:
            loop += profile_data["additional_params"]["retransmit"]

    # If loop is set to 0 or less (user defined retranmit as minus value), go inifinite on this profile.
    # If retransmit was not defined, do once.
    while i < loop or loop <= 0: 
        is_tcp = 0
        no_wait = 0
        if loop > 0:
            i += 1
        for pkt in profile_data["packets"]:
            p = prepare_packet(profile_data, pkt)
            
            if "TCP" in profile_data["protocol"]:
                is_tcp = 1
            
            if "flags" in pkt:
                pkt_flags = pkt["flags"]
                if "no_wait" in pkt_flags:
                    no_wait = pkt_flags["no_wait"]
            if not send_packet(p, no_wait, is_tcp):
                # No response, no need to try next packets.
                break

        CACHED_DATA["source_port"] = random.randint(1024, 65535)

def get_all_data():
    with open('data.json') as file:
        data = json.load(file)
        return data


def prepare_profile(all_data, profile_name):
    print("Getting profile details..")
    if profile_name not in all_data:
        return None
    
    profile_data = all_data[profile_name]

    if "protocol" not in profile_data:
        print("No protocol defined.")
        return None

    for proto in profile_data["protocol"]: 
        if proto not in VALID_PROTOCOLS:
            print("Invalid protocol.")
            return None

    if "packets" not in profile_data or not len(profile_data["packets"]):
        print("Empty packet list.")
        return None

    return all_data[profile_name]


def drop_packets():
    print("***** Droping outgoing RST / FIN packets *****")
    print("***** You may want to do the same on the server *****")
    print("***** iptables -I OUTPUT -p tcp --tcp-flags XXX YYY -j DROP *****")
    
    cmds =  ["iptables -F",
            "iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP",
            "iptables -I OUTPUT -p tcp --tcp-flags FIN FIN -j DROP",
            "iptables -I OUTPUT -p tcp --tcp-flags FIN ACK -j DROP"]

    for cmd in cmds:
        os.system(cmd)
    
        
    

main()
