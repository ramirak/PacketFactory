

def is_valid_IPv4(ip_addr):
    return True


def is_valid_mac(mac_addr):
    return True


def is_valid_port(port):
    if port >= 0 and port <= 65535:
        return True
    return False
