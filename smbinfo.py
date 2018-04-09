#!/usr/bin/env python3
import os
import sys
import time
import socks
import socket
import struct
import argparse
import binascii
import datetime
import logging
import concurrent.futures
import threading
import xml.etree.ElementTree as ET

from lib.utils import get_smb_info

def get_smb_info_thread(addr, args):
    info = get_smb_info(addr, args.timeout, args.smb_port)
    if args.version:
        if info['auth_realm'] == 'workgroup':
            s = '{} (nativelm:{}) (kernel:{}) (build:{}) (workgroup:{}) (name:{})'.format(
                addr, info.get('native_lm', ''), info.get('kernel', ''), info.get('build', ''),
                info['netbios_domain'], info['netbios_name'])
        else:
            s = '{} (nativelm:{}) (kernel:{}) (build:{}) (domain:{}) (name:{})'.format(
                addr, info.get('native_lm', ''), info.get('kernel', ''), info.get('build', ''),
                info['dns_domain'], info['dns_name'].split('.')[0])
    else:
        s =  'Address:       {}\n'.format(addr)
        s += 'Negotiated:    {}\n'.format(info['smbNegotiated'])
        s += 'Build:         {}\n'.format(info.get('build', ''))
        s += 'Kernel:        {}\n'.format(info.get('kernel', ''))
        s += 'NativeOS:      {}\n'.format(info.get('native_os', ''))
        s += 'NativeLM:      {}\n'.format(info.get('native_lm', ''))
        s += 'Available:     {}\n'.format(info['smbVersions'])
        s += 'SMB1Signing:   {}\n'.format(info.get('smb1_signing', ''))
        s += 'SMB2Signing:   {}\n'.format(info.get('smb2_signing', ''))
        s += 'Uptime:        {}\n'.format(info.get('uptime', ''))
        s += 'Date:          {}\n'.format(info.get('date', ''))
        s += 'AuthRealm:     {}\n'.format(info['auth_realm'])
        s += 'DnsDomain:     {}\n'.format(info['dns_domain'])
        s += 'DnsName:       {}\n'.format(info['dns_name'])
        s += 'NetBIOSDomain: {}\n'.format(info['netbios_domain'])
        s += 'NetBIOSName:   {}\n'.format(info['netbios_name'])
    s += os.linesep
    sys.stdout.write(s)

parser = argparse.ArgumentParser()
parser.add_argument('hosts', nargs='*', default=[], help='addresses to scan')
grp = parser.add_mutually_exclusive_group()
grp.add_argument('-v', '--version', action='store_true', help='get os/domain info on a single line')
parser.add_argument('-f', '--file', help='address file, 1 per line')
parser.add_argument('-x', '--nmap', help='nmap xml file. checks for open 445 or --smb-port')
parser.add_argument('-t', '--timeout', type=float, default=2, help='socket timeout in seconds. default 2')
parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='default 445')
parser.add_argument('-w', '--threads', type=int, default=20, help='worker thread count. defaults to 20')
parser.add_argument('--proxy', help='socks5 proxy: eg 127.0.0.1:8888')
parser.add_argument('--debug', action='store_true', help='enable debug output')

args = parser.parse_args()
hosts = set(args.hosts)

if args.debug:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
    for n in [__name__, 'plugins', 'lib']:
        l = logging.getLogger(n)
        l.setLevel(logging.DEBUG)
        l.addHandler(h)

if args.proxy:
    proxy_host, proxy_port = args.proxy.split(':')
    socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
    socket.socket = socks.socksocket
    dns.query.socket_factory = socks.socksocket

if args.nmap:
    scan = ET.parse(args.nmap).getroot()
    if not scan.tag == 'nmaprun':
        print('File is not nmap xml: '+args.nmap)
        sys.exit()
    for host in scan.findall('./host'):
        ports = [int(p.get('portid')) for p in host.findall('./ports/port') if p.find('state').get('state') == 'open']
        if args.smb_port in ports:
            hosts.add([e.get('addr') for e in host.findall('./address') if e.get('addrtype') == 'ipv4'][0])
if args.file:
    for addr in open(args.file):
        hosts.add(addr.strip())
if len(hosts) == 0:
    print('Must specify hosts with --file or use positional args')
    sys.exit()
with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
    concurrent.futures.wait([e.submit(get_smb_info_thread, h, args) for h in set(hosts)])
