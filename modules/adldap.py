import math
import ldap3
import socket
import logging
import binascii
import subprocess

from modules.adldap import *
from modules.convert import *
from modules.names import *
from modules.config import MAX_PAGE_SIZE

logger = logging.getLogger(__name__)

# chars to escape for Active Directory
escape_trans = str.maketrans(
    {'*': r'\2a',
     '(': r'\28',
     ')': r'\29',
     '\\': r'\5c',
     '\x00': r'\00',
     '/': r'\2f'})

def escape(s):
    ''' https://msdn.microsoft.com/en-us/library/aa746475(v=vs.85).aspx '''
    return s.translate(escape_trans)

def get_all(conn, search_base, simple_filter, attributes=[]):
    # TODO determine if dc supports paging
    return get_all_paged(conn, search_base, simple_filter, attributes)

def get_all_paged(conn, search_base, simple_filter, attributes=[]):
    ''' Fetch all results with paging. Not all DCs support this '''
    conn.search(search_base, simple_filter, attributes=attributes, paged_size=MAX_PAGE_SIZE)
    return conn.response

def get_all_wildcard(conn, search_base, simple_filter, attributes=[]):
    ''' TODO this is broken
    Fetch all results using wildcards in the CN
    '''
    if '(cn' in simple_filter.lower():
        raise ValueError('search filter must not contain CN')

    cs = '0123456789abcdefghijklmnopqrstuvwxyz'
    l, r = cs[0], cs[-1]
    ft = '(&{}(cn>={})(cn<={}))'
    results = []
    while 1:
        f = ft.format(simple_filter, l, r)
        conn.search(search_base, f, attributes=attributes)
        if conn.result['result'] == 4:
            # reached max results
            if cs.index(l) == cs.index(r) + 1:
                logger.debug('Failed to limit results. Moving on')
                results.extend(conn.response)
                ft = '(&{}(!(cn<={}))(cn<={}))'
                l = r
                r = cs[-1]
            else:
                r = cs[cs.index(l)+1]
        elif r == cs[-1]:
            # done
            results.extend(conn.response)
            break
        else:
            results.extend(conn.response)
            ft = '(&{}(!(cn<={}))(cn<={}))'
            l = r
            r = cs[-1]
    return results

def get_users(conn, search_base):
    ''' get all domain users '''
    return get_all(conn, search_base, '(objectCategory=user)', ['userPrincipalName', 'samAccountName', 'objectSid'])

def get_groups(conn, search_base):
    ''' get all domain groups '''
    # use domain as base to get builtin and domain groups in one query
    # alternatively, you can do 2 queries with bases:
    #    cn=users,cn=mydomain,cn=com
    #    cn=users,cn=builtins,cn=mydomain,cn=com
    results = get_all(conn, search_base, '(objectCategory=group)', ['objectSid', 'groupType'])
    return [g for g in results if g.get('dn', None)]

# ms-Mcs-AdmPwd (LAPS password). see also post/windows/gather/credentials/enum_laps
# mcs-AdmPwdExpirationTime can be used to determine if LAPS is in use from any authenticated user.
# ref https://adsecurity.org/?p=3164
COMPUTER_ATTRIBUTES=['name', 'dNSHostName', 'whenCreated', 'operatingSystem',
                     'operatingSystemServicePack', 'lastLogon', 'logonCount',
                     'operatingSystemHotfix', 'operatingSystemVersion',
                     'location', 'managedBy', 'description', 'ms-Mcs-AdmPwd', 'mcs-AdmPwdExpirationTime']

def get_computer(conn, search_base, cn, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    conn.search(search_base, '(&(objectCategory=computer)(cn={}))'.format(cn), attributes=attributes)
    return conn.response[0]

def get_computers(conn, search_base, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    results = get_all(conn, search_base, '(objectCategory=computer)', attributes)
    return [g for g in results if g.get('dn', None)]

def get_user_dn(conn, search_base, user):
    conn.search(search_base, '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})(samAccountName={})))'.format(user, user, user))
    return conn.response[0]['dn']

def get_user_groups(conn, search_base, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn'''
    conn.search(search_base, '(&(objectCategory=User)(distinguishedName='+user+'))', attributes=['memberOf', 'primaryGroupID'])
    group_dns = conn.response[0]['attributes']['memberOf']

    # get primary group which is not included in the memberOf attribute
    pgid = int(conn.response[0]['attributes']['primaryGroupID'][0])
    groups = get_groups(conn, search_base)
    for g in groups:
        # Builtin group SIDs are returned as str's, not bytes
        if type(g['attributes']['objectSid'][0]) == str:
            g['attributes']['objectSid'][0] = g['attributes']['objectSid'][0].encode()
    gids = [gid_from_sid(g['attributes']['objectSid'][0]) for g in groups]
    group_dns.append(groups[gids.index(pgid)]['dn'])
    group_dns = list(map(str.lower, group_dns))
    return [g for g in groups if g['dn'].lower() in group_dns]

def get_users_in_group(conn, search_base, group):
    ''' return all members of group '''
    groups = get_groups(conn, search_base)
    if group.find('=') > 0:
        group = [g for g in groups if g.get('dn', '').lower() == group.lower()][0] # get group dn
    else:
        group = [g for g in groups if cn(g.get('dn', '')).lower() == group.lower()][0] # get group dn
    gid = gid_from_sid(group['attributes']['objectSid'][0])
    # get all users with primaryGroupID of gid
    conn.search(search_base, '(&(objectCategory=user)(primaryGroupID={}))'.format(gid),
                attributes=['distinguishedName', 'userPrincipalName', 'samAccountName'])
    users = [u for u in conn.response if u.get('dn', False)]
    # get all users in group using "memberOf" attribute. primary group is not included in the "memberOf" attribute
    conn.search(search_base, '(&(objectCategory=user)(memberOf='+group['dn']+'))', attributes=['distinguishedName', 'userPrincipalName'])
    users += [u for u in conn.response if u.get('dn', False)]
    return users


def get_user_info(conn, search_base, user):
    user_dn = get_user_dn(conn, search_base, user)
    conn.search(search_base, '(&(objectCategory=user)(distinguishedName={}))'.format(escape(user_dn)), attributes=['allowedAttributes'])
    allowed = set([a.lower() for a in conn.response[0]['attributes']['allowedAttributes']])
    attributes = [
        #'msexchhomeservername',
        #'usncreated',
        'whenCreated',
        'whenChanged',
        'memberOf',
        'groupMembershipSAM',
        'accountExpires',
        'msDS-UserPasswordExpiryTimeComputed',
        'displayName',
        'primaryGroupID',
        #'homeDirectory',
        'lastLogonTimestamp',
        'lastLogon',
        'lastLogoff',
        'logonWorkstation',
        'otherLoginWorkstations',
        'scriptPath',
        'userWorkstations',
        'displayName',
        'mail',
        'title',
        'samaccountname',
        'lockouttime',
        'lockoutduration',
        'description',
        'pwdlastset',
        'logoncount',
        'logonHours',
        'name',
        #'usnchanged',
        #'allowedAttributes',
        #'admincount',
        'badpasswordtime',
        'badPwdCount',
        'info',
        'distinguishedname',
        'userPrincipalName',
        'givenname',
        'middleName',
        'lastlogontimestamp',
        'useraccountcontrol',
        'objectGUID',
        'objectSid',
    ]
    attrs = [a for a in attributes if a.lower() in allowed]
    conn.search(search_base, '(&(objectCategory=user)(distinguishedName={}))'.format(escape(user_dn)), attributes=attrs)
    return conn.response


def get_dc_info(args, conn=None):
    if not conn:
        server = ldap3.Server(args.server)
        conn = ldap3.Connection(server, auto_bind=True, version=args.version, receive_timeout=args.timeout)
    conn.search('', '(objectClass=*)', search_scope=ldap3.BASE, dereference_aliases=ldap3.DEREF_NEVER,
                attributes=['dnsHostName', 'supportedLDAPVersion', 'rootDomainNamingContext',
                            'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality'])
    r = conn.response[0]['raw_attributes']
    for a in r:
        if a == 'supportedLDAPVersion':
            r[a] = list(sorted(map(int, r[a])))
        elif type(r[a][0]) == bytes:
            r[a] = r[a][0].decode()
            if a.endswith('Functionality'):
                r[a] = int(r[a])
        else:
            r[a] = r[a][0]
    r['search_base'] = 'DC='+r['dnsHostName'].split('.', maxsplit=1)[0]+','+r['rootDomainNamingContext']
    return r
