import logging

import ad.dc
import ad.connection
from ad.convert import sid_to_str

logger = logging.getLogger(__name__)

PLUGIN_NAME='dcinfo'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    func_levels = {
        0:'2000',
        1:'2003_Mixed_Domains',
        2:'2003',
        3:'2008',
        4:'2008r2',
        5:'2012',
        6:'2012r2',
        7:'2016',
    }
    servers = ad.dc.get_domain_controllers_by_ldap(ad.connection.get(args), args.search_base, args.name_server, args.timeout)
    for s in servers:
        logger.debug('Connecting to DC {} ({})'.format(s['hostname'], s['address']))
        try:
            r = ad.dc.get_info(args, ad.connection.get(args, s['address']))
        except:
            logger.error('DC connection failed: {} ({})'.format(s['hostname'], s['address']))
            continue
        print('address                         ', s['address'])
        print('dnsHostName                     ', r['dnsHostName'])
        print('supportedLDAPVersions           ', ', '.join(map(str, r['supportedLDAPVersion'])))
        print('searchBase                      ', r['search_base'])
        print('domainControllerFunctionality   ', func_levels[r['domainControllerFunctionality']])
        print('domainFunctionality             ', func_levels[r['domainFunctionality']])
        print('forestFunctionality             ', func_levels[r['forestFunctionality']])
        print('SID                             ', sid_to_str(s['sid']))
        print()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='retrieve DC info')
        g_parser.set_defaults(handler=handler)
    return g_parser

