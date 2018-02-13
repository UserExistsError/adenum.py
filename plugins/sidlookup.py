import logging
from modules.adldap import *
from modules.convert import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='sidlookup'
g_parser = None

def handler(args, conn):
    sidstr = ''
    for s in args.sids:
        sidstr += '(objectSid={})'.format(s)
    conn.search(args.search_base, '(&(objectCategory=user)(|{}))'.format(sidstr), attributes=['objectSid', 'userPrincipalName', 'samAccountName'])
    for r in conn.response:
        name = r['dn'] if args.dn else r['cn']
        print(name, r['attributes']['objectSid'])

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='resolve SID to username')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('sids', nargs='+', help='lookup user SIDs')
    return g_parser
