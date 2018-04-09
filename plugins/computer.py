import os
import sys
import logging
import concurrent.futures

from plugins.computers import computer_info
from lib.adldap import *
# from lib.convert import *
# from lib.names import *
from lib.utils import *
from lib.config import *

logger = logging.getLogger(__name__)


PLUGIN_NAME='computer'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    for host in args.hosts:
        if is_addr(host):
            host = get_fqdn_by_addr(host, name_server=args.name_server, timeout=args.timeout)
        if host:
            computer = get_computer(conn, args.search_base, host, args.attributes)
            computer_info(computer, args)

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list computer')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-s', '--smbinfo', action='store_true', help='run smbinfo on each host')
        g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        g_parser.add_argument('-a', '--attributes', default=[], type=lambda x:x.split(','),
                              help='additional attributes to retrieve')
        g_parser.add_argument('--alive', action='store_true', help='only show alive hosts')
        g_parser.add_argument('hosts', nargs='*', default=[], help='hostname or address')
    return g_parser
