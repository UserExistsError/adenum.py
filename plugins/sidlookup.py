import logging
from modules.adldap import *
from modules.convert import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='sidlookup'
g_parser = None

def handler(args, conn):
    sidstr = ''
    for s in args.sids:
        sid_hex = sid_to_ldap(str_to_sid(s))
        sidstr += '(objectSid={})'.format(sid_hex)
    conn.search(args.search_base, '(|{})'.format(sidstr), attributes=['objectSid', 'userPrincipalName', 'samAccountName', 'cn'])
    for r in conn.response:
        print(r)
        a = r['attributes']
        if args.dn:
            name = r['dn']
        elif len(a['samAccountName']):
            name = a['samAccountName'][0]
        elif len(a['userPrincipalName']):
            name = a['userPrincipalName'][0]
        else:
            name = r['attributes']['cn'][0]
        print(name, sid_to_str(r['attributes']['objectSid'][0]))

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='resolve SID to username')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('sids', nargs='+', help='lookup user SIDs')
    return g_parser
