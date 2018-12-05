import os
import sys
import logging
import concurrent.futures

import ad.computer
import net.name
from net.util import ping_host
from ad.adsmb import get_smb_info
from ad.convert import get_attr, ft_to_str, gt_to_str, dn_to_cn

logger = logging.getLogger(__name__)


PLUGIN_NAME='computers'
g_parser = None

def get_parser():
    return g_parser


def computer_info(computer, args):
    ''' runs as a thread to resolve and find uptime of the host '''
    if len(computer['attributes']['dNSHostName']):
        hostname = computer['attributes']['dNSHostName'][0]
    else:
        hostname = computer['attributes']['name'][0]

    info = ''
    if args.resolve or args.smbinfo or args.active:
        for name_server in set([args.name_server, args.server, None]):
            addr = net.name.get_addr_by_host(hostname, name_server, args.timeout)
            if addr:
                break
        if addr:
            if args.active and not ping_host(addr, args.timeout):
                logger.debug('Host '+addr+' is down')
                return
            info = 'Address: {}\n'.format(addr)
            if args.smbinfo:
                smbinfo = get_smb_info(addr, args.timeout, args.smb_port)
                if smbinfo:
                    for k in sorted(smbinfo.keys()):
                        info += '{}: {}\n'.format(k, smbinfo[k])
        elif args.active:
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
        sys.stdout.write('cn: '+dn_to_cn(computer['dn']) + os.linesep + info + os.linesep)

def computer_info_wrapper(computer, args):
    try:
        computer_info(computer, args)
    except Exception as e:
        logger.error('Computer info {}: {}'.format(get_attr(computer, 'dNSHostName', ''), e))

def handler(args, conn):
    computers = ad.computer.get_all(conn, args.search_base, attributes=args.attributes)
    if args.basic:
        for c in computers:
            print(c['attributes']['dNSHostName'][0], c['attributes']['distinguishedName'][0])
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
            concurrent.futures.wait([e.submit(computer_info_wrapper, c, args) for c in computers])

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list computers')
        g_parser.set_defaults(handler=handler)
        g_parser.set_defaults(computers=[])
        g_parser.add_argument('-s', '--smbinfo', action='store_true', help='run smbinfo on each host')
        g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        g_parser.add_argument('--attributes', default=[], type=lambda x:x.split(','),
                              help='additional attributes to retrieve')
        g_parser.add_argument('-a', '--active', action='store_true', help='only show active hosts')
        g_parser.add_argument('--basic', action='store_true', help='get basic computer info')
    return g_parser
