import logging
from lib.adldap import *
from lib.convert import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='fsp'
g_parser = None

def handler(args, conn):
    response = conn.searchg(args.search_base, '(objectClass=foreignSecurityPrincipal)',
                           attributes=[], search_scope=ldap3.SUBTREE)
    for r in response:
        print(r['dn'])

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list foreignSecurityPrincipals')
        g_parser.set_defaults(handler=handler)
    return g_parser
