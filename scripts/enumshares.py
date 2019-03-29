#!/usr/bin/env python3
import sys
import logging
import binascii
import argparse
import concurrent.futures

import smb
from smb.SMBConnection import SMBConnection

logger = logging.getLogger(__name__)

class MyMD4Class():
    ''' class to add pass-the-hash support to pysmb '''
    @staticmethod
    def new():
        return MyMD4Class()
    def update(self, p):
        self.nthash = binascii.unhexlify(p.decode('utf-16-le'))
    def digest(self):
        return self.nthash

def crawl_share(conn, share):
    dirs = ['']
    while len(dirs) > 0:
        path = dirs.pop(0)
        try:
            for f in conn.listPath(share, path):
                if f.isDirectory:
                    if f.filename not in ['.', '..']:
                        dirs.append(path+'\\'+f.filename)
                else:
                    sys.stdout.write('\\\\{}\\{}{}\\{}\n'.format(conn.remote_name, share, path, f.filename))
        except Exception as e:
            logger.error('Error listing {}\\{}: {}'.format(share, path, str(e).split('\n')[0]))

def enum_thread(args, host):
    logger.debug('Connecting to {} as {}\\{}'.format(host, args.domain or '', args.username))
    conn = SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
    conn.connect(host, port=args.smb_port)
    shares = [s.name for s in conn.listShares() if s.type == smb.base.SharedDevice.DISK_TREE]
    for s in shares:
        logger.debug('Crawling share '+s)
        crawl_share(conn, s)
    conn.close()

def enum_shares(args):
    if args.nthash:
        logger.debug('passing the NTLM hash')
        smb.ntlm.MD4 = MyMD4Class.new
    hosts = list(args.hosts)

    # check for CIDR, then expand
    from netaddr import IPNetwork
    newhosts = []
    for h in hosts:
        if "/" in h:
            newhosts.extend([str(ip) for ip in IPNetwork(h)])
        else:
            newhosts.append(h)

    hosts = newhosts

    if args.filename:
        for l in open(args.filename):
            if "/" in l.strip():
                hosts.extend([str(ip) for ip in IPNetwork(l.strip())])
            else:
                hosts.append(l.strip())
        #hosts.extend([l.strip() for l in open(args.filename)])
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as e:
        concurrent.futures.wait([e.submit(enum_thread, args, h) for h in set(hosts)])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='username')
    parser.add_argument('-p', '--password', required=True, help='password')
    parser.add_argument('-d', '--domain', default='.', help='AD domain')
    parser.add_argument('-w', '--workers', default=1, type=int, help='worker threads')
    parser.add_argument('--nthash', action='store_true', help='password is the nthash')
    parser.add_argument('-f', '--filename', help='file of hosts')
    parser.add_argument('hosts', nargs='*', help='server')
    parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='SMB port. default 445')
    #parser.add_argument('--proxy', help='socks5 proxy: eg 127.0.0.1:8888')
    parser.add_argument('--debug', action='store_true', help='enable debug output')
    args = parser.parse_args()

    if args.debug:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
        for n in [__name__]:
            l = logging.getLogger(n)
            l.setLevel(logging.DEBUG)
            l.addHandler(h)

    enum_shares(args)
