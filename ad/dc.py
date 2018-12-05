import ldap3
import logging

from net.name import get_addr_by_host, get_fqdn_by_addr
from config import TIMEOUT

logger = logging.getLogger(__name__)

def get_info(args, conn=None):
    if not conn:
        server = ldap3.Server(args.server, args.port)
        conn = ldap3.Connection(server, auto_bind=True, version=args.version, receive_timeout=args.timeout)
    conn.search(
        '',
        '(objectClass=*)',
        search_scope=ldap3.BASE,
        dereference_aliases=ldap3.DEREF_NEVER,
        attributes=[
            'dnsHostName',
            'supportedLDAPVersion',
            'rootDomainNamingContext',
            'domainFunctionality',
            'forestFunctionality',
            'domainControllerFunctionality',
            'defaultNamingContext',
            'supportedLDAPPolicies'
        ]
    )
    r = conn.response[0]['raw_attributes']
    for a in r:
        if a == 'supportedLDAPVersion':
            r[a] = list(sorted(map(int, r[a])))
        elif type(r[a][0]) == bytes:
            r[a] = r[a][0].decode()
            if a.endswith('Functionality'):
                r[a] = int(r[a])
        else:
            r[a] = r[a][0]
    r['search_base'] = 'DC='+r['dnsHostName'].split('.', maxsplit=1)[0]+','+r['rootDomainNamingContext']
    return r


def get_domain_controllers_by_ldap(conn, search_base, name_server=None, timeout=TIMEOUT):
    # or primaryGroupID = 516 (GROUP_RID_CONTROLLERS)
    search_base = 'OU=Domain Controllers,'+search_base
    response = conn.searchg(
        search_base,
        '(objectCategory=computer)',
        search_scope=ldap3.SUBTREE,
        attributes=['dNSHostName', 'objectSid'])
    servers = []
    for s in response:
        hostname = s['attributes']['dNSHostName'][0]
        addr = get_addr_by_host(hostname, name_server, timeout) or \
               get_addr_by_host(hostname, conn.server.host, timeout)
        if addr:
            servers.append({'address':addr, 'hostname':hostname, 'sid':s['attributes']['objectSid'][0]})
    return servers

def get_domain_controllers_by_dns(domain, name_server=None, timeout=TIMEOUT):
    ''' return the domain controller addresses for a given domain '''
    resolver = get_resolver(name_server, timeout)
    queries = [
        ('_ldap._tcp.dc._msdcs.'+domain, 'SRV'), # joining domain
        ('_ldap._tcp.'+domain, 'SRV'),
        (domain, 'A'),
        (domain, 'AAAA'),
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
        else:
            answer = []
    servers = []
    for a in answer:
        hostname = str(a).split()[-1]
        addr = get_addr_by_host(hostname, name_server, timeout)
        if addr:
            servers.append({'address':addr, 'hostname':hostname})
    return servers

def addr_to_fqdn(addr, name_servers=[], conn=None, args=None, port=445, timeout=TIMEOUT):
    ''' get the hosts domain, fully qualified, any way we can. try SMB first since all
    domain controllers should have 445 open. also, if you are forwarding your connection,
    this method will get the correct hostname. aborts for 127. ips if SMB fails '''
    is_loopback = addr.startswith('127.') or addr == '::1'
    if not is_loopback:
        if None not in name_servers:
            name_servers.append(None) # use default name server
        logger.debug('Getting domain for {} by DNS'.format(addr))
        for ns in name_servers:
            fqdn = get_fqdn_by_addr(addr, ns, timeout)
            if fqdn:
                return fqdn
        if conn and args:
            logger.debug('Getting domain for {} by LDAP'.format(addr))
            info = ad.dc.get_info(args, conn)
            try:
                return info['dnsHostName']
            except:
                pass
    logger.debug('Getting domain for {} by SMB NTLMSSP'.format(addr))
    info = get_smb_info(addr, timeout, port)
    if info and info.get('dns_name', None):
        return info.get('dns_name')
    return None
