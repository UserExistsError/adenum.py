import os
import sys
import ldap3
import socket
import struct
import logging
import binascii
import datetime
import subprocess

from modules.utils import *
from modules.names import *
from modules.config import *
from modules.convert import *


logger = logging.getLogger(__name__)
TIMEOUT = 2

private_addrs = (
    [2130706432, 4278190080], # 127.0.0.0,   255.0.0.0
    [3232235520, 4294901760], # 192.168.0.0, 255.255.0.0
    [2886729728, 4293918720], # 172.16.0.0,  255.240.0.0
    [167772160,  4278190080], # 10.0.0.0,    255.0.0.0
)

def get_domain_controllers_by_ldap(conn, search_base, name_server=None, timeout=TIMEOUT):
    search_base = 'OU=Domain Controllers,'+search_base
    conn.search(search_base, '(objectCategory=computer)', search_scope=ldap3.LEVEL, attributes=['dNSHostName'])
    servers = []
    for s in conn.response:
        hostname = s['attributes']['dNSHostName'][0]
        addr = get_addr_by_host(hostname, name_server, timeout) or \
               get_addr_by_host(hostname, conn.server.host, timeout)
        if addr:
            servers.append([addr, hostname])
    return servers

def get_domain_controllers_by_dns(domain, name_server=None, timeout=TIMEOUT):
    ''' return the domain controller addresses for a given domain '''
    resolver = get_resolver(name_server, timeout)
    queries = [
        ('_ldap._tcp.dc._msdcs.'+domain, 'SRV'), # joining domain
        ('_ldap._tcp.'+domain, 'SRV'),
        (domain, 'A'),
    ]
    answer = None
    for q in queries:
        try:
            logger.debug('Resolving {} via {}'.format(q[0], name_server or 'default'))
            answer = resolver.query(q[0], q[1])
            logger.debug('Answer '+str(answer[0]).split()[-1])
            break
        except Exception as e:
            logger.debug('Failed to resolve {} via {}'.format(q[0], name_server or 'default'))
    if not answer:
        # last, try using the default name lookup for your host (may include hosts file)
        addr = get_host_by_name(domain)
        if addr:
            answer = [addr]
    servers = []
    for a in answer:
        hostname = str(a).split()[-1]
        addr = get_addr_by_host(hostname, name_server, timeout)
        if addr:
            servers.append([addr, hostname])
    return servers


def is_private_addr(addr):
    addr = int.from_bytes(socket.inet_aton(addr), 'big')
    for a in private_addrs:
        if (addr & a[1]) == a[0]:
            return True
    return False

def is_addr(a):
    try:
        socket.inet_aton(a)
    except:
        return False
    return True


def ping_host(addr, timeout=TIMEOUT):
    ''' check if host is alive by first calling out to ping, then
    by initiating a connection on tcp/445 '''
    if not is_addr(addr):
        return False
    if sys.platform.lower().startswith('windows'):
        cmd = 'ping -n 1 -w {} {}'.format(int(timeout), addr)
    else:
        cmd = 'ping -c 1 -W {} {}'.format(int(timeout), addr)
    logger.debug('Running '+cmd)
    try:
        subprocess.check_call(cmd.split(), stderr=subprocess.STDOUT, stdout=open(os.devnull, 'w'))
        return True
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    logger.debug('Connecting to {}:445'.format(addr))
    try:
        s.connect((addr, 445))
        return True
    except socket.timeout:
        return False

def parse_target_info(ti, info):
    ''' parse the target info section of an NTLMSSP negotiation '''
    if ti == b'\x00\x00\x00\x00':
        return
    t, l = struct.unpack('<HH', ti[:4])
    v = ti[4:4+l]
    logger.debug('TargetInfoType '+hex(t))
    if t == 0x1:
        info['netbios_name'] = v.decode('utf-16-le')
    elif t == 0x2:
        info['netbios_domain'] = v.decode('utf-16-le')
    elif t == 0x3:
        info['dns_name'] = v.decode('utf-16-le')
    elif t == 0x4:
        info['dns_domain'] = v.decode('utf-16-le')
    # elif t == 0x5:
    #     info['dns_tree_name'] = v.decode('utf-16-le')
    # elif t == 0x7:
    #     info['time'] = filetime_to_str(struct.unpack('<Q', v)[0])
    parse_target_info(ti[4+l:], info)

def addr_to_fqdn(addr, name_servers=[], conn=None, args=None, port=445, timeout=TIMEOUT):
    ''' get the hosts domain, fully qualified, any way we can. try SMB first since all
    domain controllers should have 445 open. also, if you are forwarding your connection,
    this method will get the correct hostname. aborts for 127. ips if SMB fails '''
    logger.debug('Getting domain for {} by SMB NTLMSSP'.format(addr))
    info = get_smb_info(addr, timeout, port)
    if info and info.get('dns_name', None):
        return info.get('dns_name')
    if addr.startswith('127.'):
        raise ValueError('Cannot do name lookup on 127 addresses')
    if None not in name_servers:
        name_servers.append(None) # use default name server
    logger.debug('Getting domain for {} by DNS'.format(addr))
    for ns in name_servers:
        fqdn = get_fqdn_by_addr(addr, ns, timeout)
        if fqdn:
            return fqdn
    if conn and args:
        logger.debug('Getting domain for {} by LDAP'.format(addr))
        info = get_dc_info(args, conn)
        try:
            return info['dnsHostName']
        except:
            pass
    return None

def get_smb_info(addr, timeout=TIMEOUT, port=445):
    info = {'smbVersions':set()}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, port))
    except Exception:
        return None

    # send SMB1 NegotiateProtocolRequest with SMB2 dialects. should lead to SMB2
    # negotiation even if SMB1 is disabled.
    s.send(binascii.unhexlify(
        b'000000d4ff534d4272000000001843c80000000000000000000000000000'
        b'feff0000000000b100025043204e4554574f524b2050524f4752414d2031'
        b'2e3000024d4943524f534f4654204e4554574f524b5320312e303300024d'
        b'4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e31'
        b'2e3000024c4d312e32583030320002444f53204c414e4d414e322e310002'
        b'4c414e4d414e322e31000253616d626100024e54204c414e4d414e20312e'
        b'3000024e54204c4d20302e31320002534d4220322e3030320002534d4220'
        b'322e3f3f3f00'
    ))
    try:
        data = s.recv(4096)
    except ConnectionResetError:
        return None

    smb1_signing = None
    smb2_signing = None
    if data[4] == 0xff:
        smb1_signing = data[39]
        # SMB1 dialects sent in the first packet above, in the same order.
        dialects = ['PC NETWORK PROGRAM 1.0', 'MICROSOFT NETWORKS 1.03', 'MICROSOFT NETWORKS 3.0',
                    'LANMAN1.0', 'LM1.2X002', 'DOS LANMAN2.1', 'LANMAN2.1', 'Samba', 'NT LANMAN 1.0',
                    'NT LM 0.12']
        info['smbNegotiated'] = dialects[struct.unpack('<H', data[37:39])[0]]
        # SessionSetup AndX Request
        s.send(binascii.unhexlify(
            b'0000009cff534d4273000000001843c8000000000000000000000000ffff'
            b'976e000001000cff000000ffff02000100000000004a000000000054c000'
            b'806100604806062b0601050502a03e303ca00e300c060a2b060104018237'
            b'02020aa22a04284e544c4d53535000010000001582086200000000280000'
            b'000000000028000000060100000000000f0055006e006900780000005300'
            b'61006d00620061000000'
            
        ))
        data = s.recv(4096)
        ntlmssp = data[data.find(b'NTLMSSP\x00\x02\x00\x00\x00'):]
    else:
        info['smbVersions'].add(2)
        smb2_signing = data[70]
        dialect = struct.unpack('<H', data[0x48:0x4a])[0]
        boot_dt = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x74:0x7c])[0] / 10000000) - 11644473600)
        system_dt = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x6c:0x74])[0] / 10000000) - 11644473600)
        up_td = system_dt - boot_dt
        boot_dt = datetime.datetime.now() - up_td
        info['uptime'] = str(up_td) + ' (booted '+ boot_dt.strftime('%H:%M:%S %d %b %Y')+')'
        info['date'] = system_dt.strftime('%H:%M:%S %d %b %Y')
        msgid = 1
        if dialect == 0x2ff:
            # send SMB2 NegotiateProtocolRequest with random client GUID and salt
            s.send(binascii.unhexlify(
                b'000000b6fe534d4240000000000000000000000000000000000000000100'
                b'000000000000000000000000000000000000000000000000000000000000'
                b'000000000000000024000800010000007f000000') + os.urandom(16) + \
                binascii.unhexlify(
                    b'780000000200000002021002220224020003020310031103000000000100'
                    b'260000000000010020000100') + os.urandom(32) + \
                binascii.unhexlify(b'00000200060000000000020001000200')
            )
            data = s.recv(4096)
            dialect = struct.unpack('<H', data[0x48:0x4a])[0]
            msgid += 1
            if dialect >= 0x300:
                info['smbVersions'].add(3)
        info['smbNegotiated'] = hex(dialect)
        logger.debug('MaxSMBVersion: '+hex(dialect))
        # send SMB2 SessionSetupRequest
        s.send(binascii.unhexlify(
            b'000000a2fe534d424000010000000000010000200000000000000000') + struct.pack('<Q', msgid) + \
            binascii.unhexlify(
                b'000000000000000000000000000000000000000000000000'
                b'000000000000000019000001010000000000000058004a00000000000000'
                b'0000604806062b0601050502a03e303ca00e300c060a2b06010401823702'
                b'020aa22a04284e544c4d5353500001000000158208620000000028000000'
                b'0000000028000000060100000000000f'
        ))
        data = s.recv(4096)
        ntlmssp = data[data.find(b'NTLMSSP\x00\x02\x00\x00\x00'):]
        s.shutdown(socket.SHUT_RDWR)

        # send SMB1 NegotiateProtocolRequest with SMB1 only dialects to fingerprint SMB1.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((addr, port))
        s.send(binascii.unhexlify(
            b'000000beff534d4272000000001843c80000000000000000000000000000'
            b'feff00000000009b00025043204e4554574f524b2050524f4752414d2031'
            b'2e3000024d4943524f534f4654204e4554574f524b5320312e303300024d'
            b'4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e31'
            b'2e3000024c4d312e32583030320002444f53204c414e4d414e322e310002'
            b'4c414e4d414e322e31000253616d626100024e54204c414e4d414e20312e'
            b'3000024e54204c4d20302e313200'
        ))
        try:
            data = s.recv(4096)
            smb1_signing = data[39]
        except (ConnectionResetError, IndexError):
            # SMB1 likely not supported
            s = None

    if s:
        # SMB1 SessionSetup with random PID
        s.send(
            binascii.unhexlify(
                b'0000009cff534d4273000000001843c800004253525350594c200000ffff') + \
            os.urandom(2) + \
            binascii.unhexlify(
                b'000001000cff000000ffff02000100000000004a000000000054c0008061'
                b'00604806062b0601050502a03e303ca00e300c060a2b0601040182370202'
                b'0aa22a04284e544c4d535350000100000015820862000000002800000000'
                b'00000028000000060100000000000f0055006e0069007800000053006100'
                b'6d00620061000000')
        )
        data = s.recv(4096)
        native_offset = 47 + struct.unpack('<H', data[43:45])[0]
        # align to 16 bits
        native_offset += native_offset % 2
        # Samba may place a 3rd "Primary Domain" field here.
        native_os, native_lm = data[native_offset:].split(b'\x00\x00\x00', maxsplit=2)[:2]
        native_os += b'\x00'
        native_lm = native_lm.rstrip(b'\x00') + b'\x00'
        info['native_os'] = native_os.decode('utf-16-le')
        info['native_lm'] = native_lm.decode('utf-16-le')
        info['smbVersions'].add(1)
        s.shutdown(socket.SHUT_RDWR)
    # get domain/workgroup info from NTLMSSP
    info['kernel'] = '{}.{}'.format(ntlmssp[48], ntlmssp[49])
    info['build'] = '{}'.format(struct.unpack('<H', ntlmssp[50:52])[0])
    flags = struct.unpack('<L', ntlmssp[20:24])[0]
    info['auth_realm'] = 'domain' if flags & 0x10000 else 'workgroup'
    ti_len = struct.unpack('<H', ntlmssp[40:42])[0]
    ti_offset = struct.unpack('<L', ntlmssp[44:48])[0]
    ti = ntlmssp[ti_offset:ti_offset+ti_len]
    logger.debug('TargetInfo-length '+str(ti_len))
    parse_target_info(ti, info)
    info['smbVersions'] = ', '.join(map(str, info['smbVersions']))
    # ref: https://blogs.technet.microsoft.com/josebda/2010/12/01/the-basics-of-smb-signing-covering-both-smb1-and-smb2/
    if smb1_signing is not None:
        if smb1_signing & 0x8:
            info['smb1_signing'] = 'required'
        elif smb1_signing & 0x4:
            info['smb1_signing'] = 'enabled'
        else:
            info['smb1_signing'] = 'disabled'
    if smb2_signing is not None:
        if smb2_signing & 0x2:
            info['smb2_signing'] = 'required'
        elif smb2_signing & 0x1:
            info['smb2_signing'] = 'enabled'
        else:
            # this should never be the case on a Windows host
            info['smb2_signing'] = 'disabled'
    return info
