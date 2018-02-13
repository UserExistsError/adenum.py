#!/usr/bin/env python2
'''
Enumerate active users on given hosts using MSRPC over SMB. The Win32 API is NetWkstaUserEnum.
Will generally require local or domain admin creds.
'''
from __future__ import print_function
import sys
import socket
import getpass
import argparse
import impacket
from multiprocessing.dummy import Pool as ThreadPool
from impacket.smbconnection import SMBConnection
from impacket.smb import STATUS_LOGON_FAILURE
from impacket.dcerpc.v5.wkst import NetrWkstaUserEnum, MAX_PREFERRED_LENGTH, MSRPC_UUID_WKST
from impacket.dcerpc.v5 import transport

def fNetrWkstaUserEnum(smbconn):
    rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\wkssvc]')
    rpc.set_smb_connection(smbconn)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_WKST)
    request = NetrWkstaUserEnum()
    request['ServerName'] = smbconn.getServerName()+'\x00'
    request['UserInfo']['Level'] = 1
    request['UserInfo']['WkstaUserInfo']['tag'] = 1
    request['PreferredMaximumLength'] = MAX_PREFERRED_LENGTH
    resp = dce.request(request)
    dce.disconnect()
    return resp

def query_thread(param):
    host, args = param
    try:
        smbconn = SMBConnection(host, host) # throws socket.error
        if args.nthash:
            # throws impacket.smbconnection.SessionError
            smbconn.login(args.username, '', nthash=args.password, domain=args.domain)
        else:
            smbconn.login(args.username, args.password, domain=args.domain)
        resp = fNetrWkstaUserEnum(smbconn) # throws impacket.dcerpc.v5.rpcrt.DCERPCException
    except Exception as e:
        sys.stdout.write('ERROR {}: {}\n'.format(host, str(e)))
        if type(e) == impacket.smbconnection.SessionError:
            if e.getErrorCode() == STATUS_LOGON_FAILURE and args.domain != '.':
                raise RuntimeError('Aborting: domain creds are invalid, preventing lockout')
        return
    sessions = {}
    for session in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
        username = session['wkui1_username'][:-1]
        logon_domain = session['wkui1_logon_domain'][:-1]
        oth_domains = session['wkui1_oth_domains'][:-1]
        logon_server = session['wkui1_logon_server'][:-1]
        k = '{}\\{}'.format(logon_domain, username)
        sessions[k.lower()] = '{} ({}) [{}] {}\\{}\n'.format(smbconn.getServerName(), smbconn.getRemoteHost(),
                                                             smbconn.getServerOS(), logon_domain, username)
    smbconn.logoff()
    sys.stdout.write(''.join(sessions.values()))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', default='')
    pass_parser = parser.add_mutually_exclusive_group()
    pass_parser.add_argument('-p', '--password', default='')
    pass_parser.add_argument('-P', '--prompt', action='store_true', default='')
    parser.add_argument('--nthash', action='store_true', help='pass NT hash as password')
    parser.add_argument('-d', '--domain', default='.', help='domain. default is local')
    parser.add_argument('-w', '--threads', type=int, default=1, help='default 1')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='socket timeout. default 2s')
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
    pool.map(query_thread, [(h, args) for h in set(args.hosts)])
