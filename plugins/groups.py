import ad.group
from ad.convert import dn_to_cn

PLUGIN_NAME='groups'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    for g in ad.group.get_all(conn, args.search_base):
        if args.dn:
            print(g['dn'])
        else:
            print(dn_to_cn(g['dn']))

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all groups')
        g_parser.set_defaults(handler=handler)
    return g_parser
