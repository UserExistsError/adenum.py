from modules.adldap import *
from modules.convert import *

PLUGIN_NAME='groups'
g_parser = None

def get_parser():
    return g_parser


def handler(args, conn):
    for g in get_groups(conn, args.search_base):
        if args.dn:
            print(g['dn'])
        else:
            print(cn(g['dn']))


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all groups')
        g_parser.set_defaults(handler=handler)
    return g_parser
