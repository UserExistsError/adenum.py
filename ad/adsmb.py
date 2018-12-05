import os
import struct
import socket
import logging
import datetime
import binascii
from ctypes import LittleEndianStructure, c_uint32

from net.util import get_tcp_socket, is_addr4, is_addr6
from config import TIMEOUT

logger = logging.getLogger(__name__)


class NegotiateFlags(LittleEndianStructure):
    _fields_ = list(reversed([
        ('NTLMSSP_NEGOTIATE_56', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_KEY_EXCH', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_128', c_uint32, 1),
        ('reserved0', c_uint32, 1),
        ('reserved1', c_uint32, 1),
        ('reserved2', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_VERSION', c_uint32, 1),
        ('reserved3', c_uint32, 1),

        ('NTLMSSP_NEGOTIATE_TARGET_INFO', c_uint32, 1),
        ('NTLMSSP_REQUEST_NON_NT_SESSION_KEY', c_uint32, 1),
        ('reserved4', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_IDENTIFY', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY', c_uint32, 1),
        ('reserved5', c_uint32, 1),
        ('NTLMSSP_TARGET_TYPE_SERVER', c_uint32, 1),
        ('NTLMSSP_TARGET_TYPE_DOMAIN', c_uint32, 1),

        ('NTLMSSP_NEGOTIATE_ALWAYS_SIGN', c_uint32, 1),
        ('reserved6', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED', c_uint32, 1),
        ('ANONYMOUS', c_uint32, 1),
        ('reserved7', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_NTLM', c_uint32, 1),
        ('reserved9', c_uint32, 1),

        ('NTLMSSP_NEGOTIATE_LM_KEY', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_DATAGRAM', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_SEAL', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_SIGN', c_uint32, 1),
        ('reserved10', c_uint32, 1),
        ('NTLMSSP_REQUEST_TARGET', c_uint32, 1),
        ('NTLM_NEGOTIATE_OEM', c_uint32, 1),
        ('NTLMSSP_NEGOTIATE_UNICODE', c_uint32, 1),
    ]))
    def __str__(self):
        s = ''
        for n, t, _ in self._fields_:
            s += '{:45s} {}\n'.format(n, getattr(self, n))
        return s

def parse_target_info(ti, info):
    ''' parse the target info section of an NTLMSSP negotiation '''
    if ti == b'\x00\x00\x00\x00':
        return
    t, l = struct.unpack('<HH', ti[:4])
    v = ti[4:4+l]
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

def get_smb_info(addr, timeout=TIMEOUT, port=445):
    def get_smb_error(data):
        # assumes smb direct over 445
        return struct.unpack('<L', data[9:13])[0]
    info = {
        'auth_realm':'',
        'build':'',
        'date':'',
        'dns_domain':'',
        'dnsHostName':'',
        'dns_name':'',
        'dns_tree_name':'',
        'kernel':'',
        'native_lm':'',
        'native_os':'',
        'netbios_domain':'',
        'netbios_name':'',
        'smb1_signing':'',
        'smb2_signing':'',
        'smbNegotiated':'',
        'smbVersions':set(),
        'time':'',
        'uptime':'',
    }

    s = get_tcp_socket(addr)
    s.settimeout(timeout)
    logger.debug('smbinfo {}:{}'.format(addr, port))

    if is_addr4(addr):
        s.connect((addr, port))
    elif is_addr6(addr):
        s.connect((addr, port, 0, 0))
    else:
        raise ValueError('Invalid address: '+addr)

    # send SMB1 NegotiateProtocolRequest with SMB2 dialects. should lead to SMB2
    # negotiation even if SMB1 is disabled.
    logger.debug('{}:{} Sending SMB1 NegotiateProtocolRequest with SMB2 dialects'.format(addr, port))
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
        logger.debug('{}:{} Failed to elicit SMB2 negotiation. Target is SMB1 only'.format(addr, port))
        smb1_signing = data[39]
        # SMB1 dialects sent in the first packet above, in the same order.
        dialects = ['PC NETWORK PROGRAM 1.0', 'MICROSOFT NETWORKS 1.03', 'MICROSOFT NETWORKS 3.0',
                    'LANMAN1.0', 'LM1.2X002', 'DOS LANMAN2.1', 'LANMAN2.1', 'Samba', 'NT LANMAN 1.0',
                    'NT LM 0.12']
        info['smbNegotiated'] = dialects[struct.unpack('<H', data[37:39])[0]]
        # SessionSetup AndX Request
        logger.debug('{}:{} Sending SMB1 SessionSetup AndX Request'.format(addr, port))
        s.send(binascii.unhexlify(
            b'0000009cff534d4273000000001843c8000000000000000000000000ffff'
            b'976e000001000cff000000ffff02000100000000004a000000000054c000'
            b'806100604806062b0601050502a03e303ca00e300c060a2b060104018237'
            b'02020aa22a04284e544c4d53535000010000001582086200000000280000'
            b'000000000028000000060100000000000f0055006e006900780000005300'
            b'61006d00620061000000'
        ))
        data = s.recv(4096)
        logger.debug('{}:{} Received SMB1 SessionSetup AndX Response'.format(addr, port))
        ntlmssp = data[data.find(b'NTLMSSP\x00\x02\x00\x00\x00'):]
    else:
        info['smbVersions'].add(2)
        smb2_signing = data[70]
        dialect = struct.unpack('<H', data[0x48:0x4a])[0]
        logger.debug('{}:{} Received SMB2 negotiation response: 0x{:x}'.format(addr, port, dialect))
        boot_dt = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x74:0x7c])[0] / 10000000) - 11644473600)
        system_dt = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x6c:0x74])[0] / 10000000) - 11644473600)
        up_td = system_dt - boot_dt
        boot_dt = datetime.datetime.now() - up_td
        info['uptime'] = str(up_td) + ' (booted '+ boot_dt.strftime('%H:%M:%S %d %b %Y')+')'
        info['date'] = system_dt.strftime('%H:%M:%S %d %b %Y')
        msgid = 1               # message id must be incremented each request
        if dialect == 0x2ff:
            # send SMB2 NegotiateProtocolRequest with random client GUID and salt
            logger.debug('{}:{} Sending SMB2 NegotiateProtocolRequest'.format(addr, port))
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
            logger.debug('{}:{} Received SMB2 NegotiateProtocolResponse: 0x{:x}'.format(addr, port, dialect))
            msgid += 1
            if dialect >= 0x300:
                info['smbVersions'].add(3)
        info['smbNegotiated'] = hex(dialect)
        # send SMB2 SessionSetupRequest
        logger.debug('{}:{} Sending SMB2 SessionSetupRequest'.format(addr, port))
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
        logger.debug('{}:{} Received SMB2 SessionSetupResponse with NTLMSSP info'.format(addr, port))
        s.shutdown(socket.SHUT_RDWR)

        # send SMB1 NegotiateProtocolRequest with SMB1 only dialects to fingerprint SMB1.
        s = get_tcp_socket(addr)
        s.settimeout(timeout)
        s.connect((addr, port))
        logger.debug('{}:{} Sending SMB1 NegotiateProtocolRequest with SMB1 only dialects'.format(addr, port))
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
            logger.debug('{}:{} Failed to receive SMB1 NegotiateProtocolResponse. SMB1 not supported'.format(addr, port))
            s = None

    if s:
        # SMB1 SessionSetup with random PID
        logger.debug('{}:{} Sending SMB1 SessionSetup request'.format(addr, port))
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
        info['smbVersions'].add(1)
        logger.debug('{}:{} Received SMB1 SessionSetup response. Parsing native strings'.format(addr, port))
        status = get_smb_error(data)
        logger.debug('SMB Status: 0x{:08x}'.format(status))
        if status == 0xc0000002: #STATUS_NOT_IMPLEMENTED. expect 0xc0000016 STATUS_MORE_PROCESSING_REQUIRED
            logger.error('Host does not support NTLM auth')
        elif status == 0xc0000022: # NTSTATUS_ACCESS_DENIED. non-standard Windows configuration?
            logger.error('Access denied')
        else:
            native_offset = 47 + struct.unpack('<H', data[43:45])[0]
            # align to 16 bits
            native_offset += native_offset % 2
            # Samba may place a 3rd "Primary Domain" field here.
            native_os, native_lm = data[native_offset:].split(b'\x00\x00\x00', maxsplit=2)[:2]
            native_os += b'\x00'
            native_lm = native_lm.rstrip(b'\x00') + b'\x00'
            info['native_os'] = native_os.decode('utf-16-le')
            info['native_lm'] = native_lm.decode('utf-16-le')
        s.shutdown(socket.SHUT_RDWR)
    if len(ntlmssp) > 1:
        # get domain/workgroup info from NTLMSSP
        info['kernel'] = '{}.{}'.format(ntlmssp[48], ntlmssp[49])
        info['build'] = '{}'.format(struct.unpack('<H', ntlmssp[50:52])[0])
        # ref: https://msdn.microsoft.com/en-us/library/cc236650.aspx
        logger.debug('flags {:08x}'.format(struct.unpack('<L', ntlmssp[20:24])[0]))
        flags = NegotiateFlags.from_buffer_copy(ntlmssp[20:24])
        info['auth_realm'] = 'domain' if flags.NTLMSSP_TARGET_TYPE_DOMAIN else 'workgroup'
        ti_len = struct.unpack('<H', ntlmssp[40:42])[0]
        ti_offset = struct.unpack('<L', ntlmssp[44:48])[0]
        ti = ntlmssp[ti_offset:ti_offset+ti_len]
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
