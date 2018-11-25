import ldap3
import logging
import binascii
import tempfile
import collections
import configparser

from lib.convert import *

logger = logging.getLogger(__name__)

# password attributes as stored in
# \\DC\sysvol\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
sysvol_attrs = [
    'MinimumPasswordLength',
    'PasswordComplexity',
    'MinimumPasswordAge',	
    'MaximumPasswordAge',
    'PasswordHistorySize',	
    'LockoutBadCount',	
    'ResetLockoutCount',	
    'LockoutDuration',
    'RequireLogonToChangePassword',	
    'ForceLogoffWhenHourExpire',	
    'ClearTextPassword',
    'LSAAnonymousNameLookup'
]

# password attributes as stored in domain properties
ldap_attrs = [
    'lockoutDuration',
    'lockOutObservationWindow',
    'pwdProperties',
    'lockoutThreshold',
    'maxPwdAge',
    'minPwdAge',
    'minPwdLength',
    'forceLogoff'
]

# maps printable attr name to name as defined in GptTmpl.inf and ldap
named_attrs = {
    'MinimumPasswordLength':('MinimumPasswordLength', 'minPwdLength'),
    'MinimumPasswordAge':('MinimumPasswordAge', 'minPwdAge'),
    'MaximumPasswordAge':('MaximumPasswordAge', 'maxPwdAge'),
    'PasswordHistorySize':('PasswordHistorySize', ''),
    'PasswordComplexity':('PasswordComplexity', 'pwdProperties'),
    'LockoutBadCount':('LockoutBadCount', 'lockoutThreshold'),
    'LockoutDuration':('LockoutDuration', 'lockoutDuration'),
    'LockoutObservationWindow':('', 'lockOutObservationWindow'),
    'ForceLogoffWhenHourExpire':('ForceLogoffWhenHourExpire', 'forceLogoff'),
    'RequireLogonToChangePassword':('RequireLogonToChangePassword', ''),
    'ClearTextPassword':('ClearTextPassword', ''),
    'LSAAnonymousNameLookup':('LSAAnonymousNameLookup', ''),
}

class MyMD4Class():
    ''' class to add pass-the-hash support to pysmb '''
    @staticmethod
    def new():
        return MyMD4Class()
    def update(self, p):
        self.nthash = binascii.unhexlify(p.decode('utf-16-le'))
    def digest(self):
        return self.nthash

def get_default_pwd_policy(args, conn):
    ''' ref https://msdn.microsoft.com/en-us/library/cc232769.aspx
    default password policy is what gets returned by "net accounts"
    The policy is stored as a GPO on the sysvol share. It's stored in an INI file.
    The default policy is not returned by get_pwd_policy()
    TODO: default policy may be stored somewhere else '''
    try:
        from smb.SMBConnection import SMBConnection
        import smb.ntlm
    except:
        logger.fatal('Failed to import pysmb')
        return None
    ldap_props = {}
    if conn:
        response = list(conn.searchg('cn=Policies,cn=System,'+args.search_base,
                               '(cn={31B2F340-016D-11D2-945F-00C04FB984F9})',
                               attributes=['gPCFileSysPath']))
        gpo_path = response[0]['attributes']['gPCFileSysPath'][0]
        response = conn.searchg(args.search_base, '(distinguishedName={})'.format(args.search_base,), ldap3.BASE,
                               attributes=ldap_attrs)
        try:
            ldap_props = response[0]['attributes']
        except:
            pass
        # ldap stores ints differently than the .inf in sysvol
        if 'minPwdAge' in ldap_props:
            ldap_props['minPwdAge'][0] = str(int(ldap_props['minPwdAge'][0])//1440) # to days
        if 'maxPwdAge' in ldap_props:
            ldap_props['maxPwdAge'][0] = str(int(ldap_props['maxPwdAge'][0])//1440) # to days
        if 'lockoutDuration' in ldap_props:
            ldap_props['lockoutDuration'][0] = str(int(ldap_props['lockoutDuration'][0])//3600) # to minutes
    else:
        gpo_path = r'\\' + args.domain + r'\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE'
    logger.debug('GPOPath '+gpo_path)
    sysvol, rel_path = gpo_path[2:].split('\\', 2)[-2:]
    rel_path += r'\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    tmp_file = tempfile.NamedTemporaryFile(prefix='GptTmpl_', suffix='.inf')
    md4_tmp = smb.ntlm.MD4
    if args.nthash:
        smb.ntlm.MD4 = MyMD4Class.new
    conn = SMBConnection(args.username, args.password, 'adenum', args.server, use_ntlm_v2=True,
                         domain=args.domain, is_direct_tcp=(args.smb_port != 139))
    logger.debug('connecting {}:{}'.format(args.server, args.smb_port))
    conn.connect(args.server, port=args.smb_port)
    smb.ntlm.MD4 = md4_tmp
    attrs, size = conn.retrieveFile(sysvol, rel_path, tmp_file)
    tmp_file.seek(0)
    inf = tmp_file.read()
    if inf[:2] == b'\xff\xfe':
        inf = inf.decode('utf-16')
    else:
        inf = inf.decode()
    config = configparser.ConfigParser(delimiters=('=', ':', ','))
    config.read_string(inf)
    sysvol_props = config['System Access']

    # merge sysvol and ldap properties
    props = collections.OrderedDict()
    for name in named_attrs:
        sname, lname = named_attrs[name]
        if sname in sysvol_props:
            props[name] = sysvol_props[sname]
        elif lname in ldap_props:
            if lname.lower() in ['lockoutduration', 'lockoutobservationwindow', 'maxpwdage', 'minpwdage']:
                props[name] = interval_to_minutes(ldap_props[lname][0])
            else:
                props[name] = ldap_props[lname][0]
    return props

def get_pwd_policy(conn, search_base):
    ''' return non-default password policies for the domain. user must have read access to
    policies in "Password Settings Container" '''
    base = 'cn=Password Settings Container,cn=System,'+search_base
    # https://technet.microsoft.com/en-us/library/2007.12.securitywatch.aspx
    attrs = [
        'name',
        'msDS-PasswordReversibleEncryptionEnabled', # default is false which is good
        'msDS-PasswordHistoryLength',               # how many old pwds to remember
        'msds-PasswordComplexityEnabled',           # require different character groups
        'msDS-MinimumPasswordLength',
        'msDS-MinimumPasswordAge', # used to prevent abuse of msDS-PasswordHistoryLength
        'msDS-MaximumPasswordAge', # how long until password expires
        'msDS-LockoutThreshold',   # login failures allowed within the window
        'msDS-LockoutObservationWindow', # time window where failed auths are counted
        'msDS-LockoutDuration', # how long to lock user account after too many failed auths
        'msDS-PSOAppliesTo',    # dn's of affected users/groups
        'msDS-PasswordSettingsPrecedence', # used to assign precedence when a user is member of multiple policies
    ]
    # grab all objects directly under the search base
    raw_response = conn.searchg(base, '(objectCategory=*)', attributes=attrs, search_scope=ldap3.LEVEL)
    response = []
    for r in raw_response:
        if not r['dn'].lower().startswith('cn=password settings container,'):
            response.append(r)
    return response
