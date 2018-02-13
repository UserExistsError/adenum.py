import socket
import logging
import dns.resolver

logger = logging.getLogger(__name__)
TIMEOUT = 2

def get_resolver(name_server=None, timeout=TIMEOUT):
    if name_server:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [name_server]
    else:
        # use nameserver configured for the host
        resolver = dns.resolver
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def get_host_by_name(host):
    logger.debug('Resolving {} via default'.format(host))
    try:
        return socket.gethostbyname(host)
    except:
        pass
    return None

def get_addrs_by_host(host, name_server=None, timeout=TIMEOUT):
    ''' return list of addresses for the host '''
    resolver = get_resolver(name_server, timeout)
    try:
        answer = resolver.query(host)
        logger.debug('Resolved {} to {} via {}'.format(host, ', '.join([a.address for a in answer]),
                                                       name_server or 'default DNS'))
    except Exception:
        logger.debug('Name resolution failed for {} via {}'.format(host, name_server or 'default'))
        return []
    return [a.address for a in answer]

def get_addr_by_host(host, name_server=None, timeout=TIMEOUT):
    addrs = get_addrs_by_host(host, name_server, timeout)
    return addrs[0] if len(addrs) else None

def get_fqdn_by_addr(addr, name_server=None, timeout=TIMEOUT):
    resolver = get_resolver(name_server, timeout)
    arpa = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
    try:
        answer = resolver.query(arpa, 'PTR', 'IN')
        logger.debug('Resolved {} to {} via {}'.format(arpa, str(answer[0])[:-1], name_server or 'default'))
    except Exception:
        logger.debug('Name resolution failed for {} via {}'.format(arpa, name_server or 'default'))
        return None
    return str(answer[0])[:-1]

def get_host_by_addr(addr, name_server=None, timeout=TIMEOUT):
    fqdn = get_fqdn_by_addr(addr, name_server, timeout)
    if fqdn:
        return fqdn.split('.', maxsplit=1)[0]
    return None
