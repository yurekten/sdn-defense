import math
import socket


def entropy(array):
    total_entropy = 0

    for i in array:
        total_entropy += -i * math.log(2, i)

    return total_entropy


def is_valid_remote_ip(ip):
    """
    validate sting ip if it is valid remote ip
    """
    try:
        socket.inet_aton(ip)

        if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168."):
            return False

        if ip.startswith("0."):
            return False

        if ip.endswith(".255"):
            return False

        return True
    except socket.error:
        return False
