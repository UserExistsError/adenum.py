import ldap3
import logging
from modules.adldap import *
from modules.convert import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='query'
g_parser = None

def get_parser():
    return g_parser

def custom_query(conn, base, _filter, scope=ldap3.SUBTREE, attrs=None):
    conn.search(base, _filter, search_scope=scope, attributes=attrs)
    return conn.response

def handler(args, conn):
    if args.scope.lower() == 'level':
        scope = ldap3.LEVEL
    elif args.scope.lower() == 'base':
        scope = ldap3.BASE
    elif args.scope.lower() in ['sub', 'subtree']:
        scope = ldap3.SUBTREE
    else:
        raise ValueError('scope must be either "level", "base", or "subtree"')

    if args.base:
        base = args.base+','+args.search_base if args.append else args.base
    elif args.base is None:
        base = args.search_base
    else:
        base = ''

    if args.allowed:
        # range doesn't seem to work...
        response = custom_query(conn, base, args.filter, scope=scope, attrs=['allowedAttributes', 'range=0-1'])
        print('AllowedAttributes')
        for a in conn.response[0]['attributes']['allowedAttributes']:
            print('\t', a)
        return

    response = custom_query(conn, base, args.filter, scope=scope, attrs=args.attributes)
    for r in response:
        if 'dn' in r:
            print(r['dn'])
            for a in args.attributes:
                print(a, get_attr(r, a, ''))
            print('')


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='perform custom ldap query')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-b', '--base', help='search base. default is DC')
        g_parser.add_argument('-a', '--append', action='store_true', default=False, help='append base to DC')
        g_parser.add_argument('-f', '--filter', required=True, help='search filter')
        g_parser.add_argument('-s', '--scope', type=str.lower,  default='base', choices=['base', 'level', 'subtree'], help='search scope')
    return g_parser
