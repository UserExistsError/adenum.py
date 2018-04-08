import struct
import datetime

def dw(d):
    ''' convert attrs stored as dwords to an int '''
    return 0 if d == 0 else 0xffffffff + d + 1

def timestr_or_never(t):
    return 'Never' if t in [0, 0x7FFFFFFFFFFFFFFF] else ft_to_str(t)

def cn(dn):
    ''' return common name from distinguished name '''
    return dn.split(',')[0].split('=')[-1]

def dt_to_lt(dt):
    ''' convert datetime object to localtime '''
    return dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)

def ft_to_dt(win):
    ''' convert windows FILETIME to datetime '''
    micros = win / 10.0
    return dt_to_lt(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=micros))

def ft_to_str(win):
    return ft_to_dt(win).strftime('%m/%d/%Y %I:%M:%S %p')

def interval_to_minutes(i):
    ''' convert interval/duration values (100 ns intervals) to seconds '''
    if type(i) == str:
        i = int(i)
    return int((-i / 10000000) / 60)

def gt_to_dt(g):
    ''' convert generalized time to datetime '''
    return dt_to_lt(datetime.datetime.strptime(g.split('.')[0], '%Y%m%d%H%M%S'))

def gt_to_str(g):
    return gt_to_dt(g).strftime('%m/%d/%Y %I:%M:%S %p')

def sid_to_ldap(sid):
    ''' convert sid to format usable in ldap queries by specifying each
    byte as \AB '''
    sid_hex = ''
    for b in sid:
        sid_hex += '\\{:02x}'.format(b)
    return sid_hex

def str_to_sid(sid_str):
    ''' convert SID as string to bytes object '''
    parts = sid_str.split('-')
    rev = int(parts[1])
    auth = int(parts[2])
    ids = parts[3:]
    sid = struct.pack('<BB', rev, len(ids))
    sid += struct.pack('>Q', auth)[2:]
    sid += struct.pack('<'+str(len(ids))+'I', *[int(i) for i in ids])
    return sid

def sid_to_str(sid):
    ''' accepts SID as returned by ldap and converts to string '''
    sid_str = 'S-{}-{}-'.format(sid[0], struct.unpack('>Q', b'\x00\x00'+sid[2:8])[0])
    ids = struct.unpack('<'+str(sid[1])+'I', sid[8:])
    sid_str += '-'.join([str(i) for i in ids])
    return sid_str

def gid_from_sid(sid):
    if type(sid) == str:
        sid = sid.encode()
    return struct.unpack('<H', sid[-4:-2])[0]

def get_attr(o, attr, default=None, trans=None):
    ''' given a dict object returned by ldap, return the first named attribute or if it
    does not exists, return default '''
    if not o.get('attributes', None):
        return default
    v = o['attributes'].get(attr, None)
    if not v:
        return default
    if type(v) == list:
        if len(v) == 0:
            return default
        v = v[0]
    if trans:
        return trans(v)
    return v

