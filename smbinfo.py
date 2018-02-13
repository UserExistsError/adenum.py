#!/usr/bin/env python3
import os
import sys
import time
import socket
import struct
import argparse
import binascii
import datetime
import concurrent.futures
import threading
import xml.etree.ElementTree as ET

from modules.utils import get_smb_info

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
        if args.all:
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
#grp.add_argument('-d', '--domain', action='store_true', help='get domain/workgroup info')
grp.add_argument('-a', '--all', action='store_true', help='get all information possible')
grp.add_argument('-v', '--version', action='store_true', help='get os/domain info on a single line')

parser.add_argument('-f', '--file', help='address file, 1 per line')
parser.add_argument('-x', '--nmap', help='nmap xml file. checks for open 445')
parser.add_argument('-t', '--timeout', type=float, default=2, help='socket timeout in seconds. default 2')
parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='default 445')
parser.add_argument('--threads', type=int, default=50, help='worker thread count. defaults to 50')

args = parser.parse_args()
hosts = set(args.hosts)
if args.nmap:
    scan = ET.parse(args.nmap).getroot()
    if not scan.tag == 'nmaprun':
        raise ValueError('file is not nmap xml')
    for host in scan.findall('./host'):
        ports = [int(p.get('portid')) for p in host.findall('./ports/port') if p.find('state').get('state') == 'open']
        if 445 in ports:
            hosts.add([e.get('addr') for e in host.findall('./address') if e.get('addrtype') == 'ipv4'][0])
if args.file:
    for addr in open(args.file):
        hosts.add(addr.strip())
with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
    concurrent.futures.wait([e.submit(get_smb_info_thread, h, args) for h in set(hosts)])
