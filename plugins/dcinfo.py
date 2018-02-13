import logging
from modules.adldap import *
from modules.convert import *
from modules.utils import *
from modules.connection import *

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
    servers = get_domain_controllers_by_ldap(get_connection(args), args.search_base, args.timeout)
    for addr, hostname in servers:
        r = get_dc_info(args, get_connection(args, addr))
        print('address                         ', addr)
        print('dnsHostName                     ', r['dnsHostName'])
        print('supportedLDAPVersions           ', ', '.join(map(str, r['supportedLDAPVersion'])))
        print('search_base                     ', r['search_base'])
        print('domainControllerFunctionality   ', func_levels[r['domainControllerFunctionality']])
        print('domainFunctionality             ', func_levels[r['domainFunctionality']])
        print('forestFunctionality             ', func_levels[r['forestFunctionality']])
        print()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='retrieve DC info')
        g_parser.set_defaults(handler=handler)
    return g_parser

