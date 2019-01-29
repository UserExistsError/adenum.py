import logging

logger = logging.getLogger(__name__)

# ms-Mcs-AdmPwd (LAPS password). see also post/windows/gather/credentials/enum_laps
# mcs-AdmPwdExpirationTime can be used to determine if LAPS is in use from any authenticated user.
# ref https://adsecurity.org/?p=3164
COMPUTER_ATTRIBUTES=[
    'name',
    'dNSHostName',
    'whenCreated',
    'operatingSystem',
    'operatingSystemServicePack',
    'lastLogon',
    'logonCount',
    'operatingSystemHotfix',
    'operatingSystemVersion',
    'location',
    'managedBy',
    'description',
    'ms-Mcs-AdmPwd',
    'mcs-AdmPwdExpirationTime'
]

def get(conn, hostname, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    if '.' in hostname:
        response = list(conn.searchg(conn.default_search_base, '(&(objectCategory=computer)(dNSHostname={}))'.format(hostname), attributes=attributes))
    else:
        response = list(conn.searchg(conn.default_search_base, '(&(objectCategory=computer)(cn={}))'.format(hostname), attributes=attributes))
    if len(response) > 1:
        logger.warning('Found multiple computers when expecting 1. Using first result only.')
    return list(response)[0]


def get_all(conn, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    response = conn.searchg(conn.default_search_base, '(objectCategory=computer)', attributes=attributes)
    return [c for c in response if c.get('dn', None)]
