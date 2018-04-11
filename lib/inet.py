import socket

private_addrs = (
    [2130706432, 4278190080], # 127.0.0.0,   255.0.0.0
    [3232235520, 4294901760], # 192.168.0.0, 255.255.0.0
    [2886729728, 4293918720], # 172.16.0.0,  255.240.0.0
    [167772160,  4278190080], # 10.0.0.0,    255.0.0.0
)

def is_private_addr(addr):
    ''' used to prevent auth over the Internet. for IPv6, return True always '''
    if is_addr6(addr):
        return True
    addr = int.from_bytes(socket.inet_aton(addr), 'big')
    for a in private_addrs:
        if (addr & a[1]) == a[0]:
            return True
    return False

def is_addr4(a):
    try:
        socket.inet_pton(socket.AF_INET, a)
        return True
    except:
        pass
    return False

def is_addr6(a):
    try:
        socket.inet_pton(socket.AF_INET6, a)
        return True
    except:
        pass
    return False

def is_addr(a):
    return is_addr4(a) or is_addr6(a) or False
