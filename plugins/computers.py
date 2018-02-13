import os
import sys
import logging
import concurrent.futures

from modules.adldap import *
from modules.convert import *
from modules.names import *
from modules.utils import *

logger = logging.getLogger(__name__)


PLUGIN_NAME='computers'
g_parser = None

def get_parser():
    return g_parser


def computer_info(computer, args):
    ''' runs as a thread to resolve and find uptime of the host '''
    hostname = computer['attributes']['dNSHostName'][0]
    info = ''
    if args.resolve or args.uptime or args.alive:
        for name_server in set([args.name_server, args.server, None]):
            addr = get_addr_by_host(hostname, name_server, args.timeout)
            if addr:
                break
        if addr:
            if args.alive and not ping_host(addr, args.timeout):
                logger.debug('Host '+addr+' is down')
                return
            info = 'Address: {}\n'.format(addr)
            if args.uptime:
                smbinfo = get_smb_info(addr, args.timeout, args.smb_port)
                if smbinfo:
                    for k in sorted(smbinfo.keys()):
                        info += '{}: {}\n'.format(k, smbinfo[k])
        elif args.alive:
            logger.debug('Host '+addr+' may be down')
            return
    for a in sorted(computer['attributes'].keys()):
        if a.lower() in ['whencreated']:
            info += '{}: {}\n'.format(a, get_attr(computer, a, '', gt_to_str))
        elif a.lower() in ['lastlogon']:
            info += '{}: {}\n'.format(a, get_attr(computer, a, '', lambda x:ft_to_str(int(x))))
        else:
            info += '{}: {}\n'.format(a, ', '.join(computer['attributes'][a]))
    if args.dn:
        sys.stdout.write('dn: '+computer['dn'] + os.linesep + info + os.linesep)
    else:
        sys.stdout.write('cn: '+cn(computer['dn']) + os.linesep + info + os.linesep)

def handler(args, conn):
    computers = get_computers(conn, args.search_base, args.attributes)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
        concurrent.futures.wait([e.submit(computer_info, c, args) for c in computers])

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list computers')
        g_parser.set_defaults(handler=handler)
        g_parser.set_defaults(computers=[])
        g_parser.add_argument('-u', '--uptime', action='store_true', help='get uptime via SMB2')
        g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        g_parser.add_argument('-a', '--attributes', default=[], type=lambda x:x.split(','),
                              help='additional attributes to retrieve')
        g_parser.add_argument('--alive', action='store_true', help='only show alive hosts')
    return g_parser
