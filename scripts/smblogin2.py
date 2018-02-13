#!/usr/bin/env python2
'''
Login to hosts and attempt to access the ADMIN$ share. ADMIN$ is used as quick check
to see if the user has administrative access on a host. Successful logins will be
reported as "Success" while successful ADMIN$ access will show "*Success".

Example

$ python2 smblogin2.py -w 20 -u Administrator -p PASSWORD -f 445.ips

Login into each newline separated host in 445.ips with 20 worker threads.
'''
from __future__ import print_function
import sys
import socket
import getpass
import argparse
import impacket
from multiprocessing.dummy import Pool as ThreadPool
from impacket.smbconnection import SMBConnection
from impacket.smb import STATUS_LOGON_FAILURE, STATUS_SUCCESS

# SMB error codes
STATUS_ACCESS_DENIED=0xc0000022
STATUS_BAD_NETWORK_NAME=0xc00000cc

def login(host, args):
    try:
        smbconn = SMBConnection(host, host, timeout=args.timeout) # throws socket.error
    except Exception as e:
        sys.stdout.write('{} {}\\{} {}\n'.format(host, args.domain, args.username+':'+args.password, 'ConnectionError'))
        return

    error_code = STATUS_SUCCESS
    try:
        if args.nthash:
            smbconn.login(args.username, '', nthash=args.password, domain=args.domain)
        elif args.nthash:
            smbconn.login(args.username, '', lmhash=args.password, domain=args.domain)
        else:
            smbconn.login(args.username, args.password, domain=args.domain)
    except impacket.smbconnection.SessionError as e:
        error_code = e.getErrorCode()

    if error_code != STATUS_SUCCESS:
        status = 'LoginError'
        if error_code == STATUS_LOGON_FAILURE:
            status = 'Failure'
            if args.domain != '.':
                raise RuntimeError('Aborting: domain creds are invalid, preventing lockout')
        sys.stdout.write('{} {}\\{} {}\n'.format(host, args.domain, args.username+':'+args.password, status))
        return

    try:
        # for s in smbconn.listShares():
        #     print(s['shi1_netname'][:-1])
        smbconn.connectTree(r'ADMIN$')
        status = '*Success'
    except Exception as e:
        error_code = e.getErrorCode()

    if error_code != STATUS_SUCCESS:
        status = 'ConnectTreeError '+hex(error_code)
        if smbconn.isGuestSession():
            status = 'Guest'
        elif error_code == STATUS_ACCESS_DENIED:
            status = 'Success'
        elif error_code == STATUS_BAD_NETWORK_NAME:
            # ADMIN$ doesn't exist, probably Samba
            status = 'ShareNameError'

    try:
        smbconn.logoff()
    except:
        pass
    sys.stdout.write('{} {}\\{} {}\n'.format(host, args.domain, args.username+':'+args.password, status))

def auth_thread(param):
    host, args = param
    try:
        login(host, args)
    except:
        sys.stdout.write('{} {}\\{} {}\n'.format(host, args.domain, args.username+':'+args.password, 'UnknownError'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', default='')
    pass_parser = parser.add_mutually_exclusive_group()
    pass_parser.add_argument('-p', '--password', default='')
    pass_parser.add_argument('-P', '--prompt', action='store_true', default='')
    hash_group = parser.add_mutually_exclusive_group()
    hash_group.add_argument('--nthash', action='store_true', help='pass NT hash as password')
    hash_group.add_argument('--lmhash', action='store_true', help='pass LM hash as password')
    parser.add_argument('-d', '--domain', default='.', help='domain. default is local')
    parser.add_argument('-w', '--threads', type=int, default=1, help='default 1')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='socket timeout. default 3s')
    parser.add_argument('-f', '--file', help='address file, 1 per line')
    parser.add_argument('hosts', nargs='*', help='hostnames or addresses')
    args = parser.parse_args()

    if args.file:
        for addr in open(args.file):
            args.hosts.append(addr.strip())

    if args.prompt:
        args.password = getpass.getpass()

    socket.setdefaulttimeout(args.timeout)
    pool = ThreadPool(args.threads)
    pool.map(auth_thread, [(h, args) for h in set(args.hosts)])
