import os
import sys
import logging

import ad.computer
from ad.convert import dn_to_cn
'''
enumerate hosts configured with "Local Administrator Password Solution" (LAPS)

ref: https://adsecurity.org/?p=3164
'''

logger = logging.getLogger(__name__)


PLUGIN_NAME='laps'
PLUGIN_INFO='''
Enumerate hosts configured with LAPS. LAPS stores local admin passwords in plaintext in the ms-Mcs-AdmPwd
attribute. This is typically readable only by privileged accounts. The mcs-AdmPwdExpirationTime can be
read by authenticated users and indicates whether a host uses LAPS or not.
'''
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    computers = ad.computer.get_all(
        conn,
        attributes=['ms-Mcs-AdmPwd', 'mcs-AdmPwdExpirationTime', 'dNSHostName'])
    for c in computers:
        if len(c['attributes']['dNSHostName']):
            info = 'dNHostName: {}\n'.format(c['attributes']['dNSHostName'][0])
        else:
            info = 'dNSHostName: {}\n'.format(c['attributes']['name'][0])

        if len(c['attributes']['ms-Mcs-AdmPwd']):
            info += 'ms-Mcs-AdmPwd: {}\n'.format(c['attributes']['ms-Mcs-AdmPwd'][0])
        else:
            info += 'ms-Mcs-AdmPwd\n'
        if len(c['attributes']['mcs-AdmPwdExpirationTime']):
            info += 'mcs-AdmPwdExpirationTime: {}\n'.format(c['attributes']['mcs-AdmPwdExpirationTime'][0])
        else:
            info += 'mcs-AdmPwdExpirationTime:\n'
        if args.dn:
            sys.stdout.write('dn: '+c['dn'] + os.linesep + info + os.linesep)
        else:
            sys.stdout.write('cn: '+dn_to_cn(c['dn']) + os.linesep + info + os.linesep)


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='query LAPS configuration for hosts')
        g_parser.set_defaults(handler=handler)
        #g_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
        #g_parser.add_argument('--alive', action='store_true', help='only show alive hosts')
    return g_parser
