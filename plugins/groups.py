import ad.group
from ad.convert import dn_to_cn, sid_to_str

PLUGIN_NAME='groups'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    for g in ad.group.get_all(conn):
        if args.dn:
            print(g['dn'], sid_to_str(g['raw_attributes']['objectSid'][0]) if args.sid else '')
        else:
            print(dn_to_cn(g['dn']), sid_to_str(g['raw_attributes']['objectSid'][0]) if args.sid else '')

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all groups')
        g_parser.add_argument('-s', '--sid', action='store_true', help='print SID')
        g_parser.set_defaults(handler=handler)
    return g_parser
