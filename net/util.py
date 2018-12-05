import sys
import socket
import logging

from config import TIMEOUT

logger = logging.getLogger(__name__)


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

def get_tcp_socket(addr):
    if is_addr4(addr):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    elif is_addr6(addr):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
    else:
        raise ValueError('Not a valid IPv4/6 addr: '+str(addr))
    return s

def ping_host(addr, timeout=TIMEOUT):
    ''' check if host is alive by first calling out to ping, then
    by initiating a connection on tcp/445 '''
    if not is_addr(addr):
        return False
    if sys.platform.lower().startswith('windows'):
        cmd = ['ping', '-n', '1', '-w', str(int(timeout)), addr]
    else:
        cmd = ['ping', '-c', '1', '-W', str(int(timeout)), addr]
    logger.debug('Running '+' '.join(cmd))
    try:
        subprocess.check_call(cmd, stderr=subprocess.STDOUT, stdout=open(os.devnull, 'w'))
        return True
    except Exception:
        pass
    s = get_tcp_socket(addr)
    s.settimeout(timeout)
    logger.debug('Connecting to {}:445'.format(addr))
    try:
        s.connect((addr, 445))
        return True
    except socket.timeout:
        pass
    return False
