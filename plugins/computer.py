import os
import sys
import logging
import concurrent.futures

import ad.computer
import net.name
import net.util
from .computers import computer_info

logger = logging.getLogger(__name__)


PLUGIN_NAME='computer'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    for host in args.hosts:
        if net.util.is_addr(host):
            host = net.name.get_fqdn_by_addr(host, name_server=args.name_server, timeout=args.timeout)
        if host:
            computer = ad.computer.get(conn, host, args.attributes)
            computer_info(computer, args)

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list computer')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-s', '--smbinfo', action='store_true', help='run smbinfo on each host')
        g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        g_parser.add_argument('--attributes', default=[], type=lambda x:x.split(','),
                              help='additional attributes to retrieve')
        g_parser.add_argument('-a', '--active', action='store_true', help='only show active hosts')
        g_parser.add_argument('hosts', nargs='*', default=[], help='hostname or address')
    return g_parser
