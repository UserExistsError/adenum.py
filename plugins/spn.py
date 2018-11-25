'''
a service principal name indicates a service run by an AD account.
it can be used to map high value accounts to a host.
'''

import ldap3
import logging

logger = logging.getLogger(__name__)

PLUGIN_NAME='spn'
g_parser = None

def handler(args, conn):
    response = conn.searchg(args.search_base, '(servicePrincipalName=*)', attributes=['servicePrincipalName'], search_scope=ldap3.SUBTREE)
    s = ''
    for r in response:
        s += '[{}]\n'.format(r['dn'])
        for spn in r['attributes']['servicePrincipalName']:
            s += '    '+spn+'\n'
        s += '\n'
    print(s, end='')

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list servicePrincipalNames for objects')
        g_parser.set_defaults(handler=handler)
    return g_parser
