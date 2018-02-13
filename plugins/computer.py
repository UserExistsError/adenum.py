import os
import sys
import logging
import concurrent.futures

from plugins.computers import computer_info
from modules.adldap import *
# from modules.convert import *
# from modules.names import *
from modules.utils import *
from modules.config import *

logger = logging.getLogger(__name__)


PLUGIN_NAME='computer'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    for c in args.hosts:
        if is_addr(c):
            fqdn = get_fqdn_by_addr(c, name_server=args.name_server, timeout=args.timeout)
            if not fqdn:
                continue
            host = fqdn.split('.', maxsplit=1)[0]
        else:
            host = c.split('.', maxsplit=1)[0]
        computer = get_computer(conn, args.search_base, host, args.attributes)
        computer_info(computer, args)

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list computer')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-u', '--uptime', action='store_true', help='get uptime via SMB2')
        g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        g_parser.add_argument('-a', '--attributes', default=[], type=lambda x:x.split(','),
                              help='additional attributes to retrieve')
        g_parser.add_argument('--alive', action='store_true', help='only show alive hosts')
        g_parser.add_argument('hosts', nargs='*', default=[], help='hostname or address')
    return g_parser
