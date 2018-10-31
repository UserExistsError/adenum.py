import math
import ldap3
import socket
import logging
import binascii
import subprocess

from lib.adldap import *
from lib.convert import *
from lib.names import *
from lib.config import MAX_PAGE_SIZE

logger = logging.getLogger(__name__)

# ms-Mcs-AdmPwd (LAPS password). see also post/windows/gather/credentials/enum_laps
# mcs-AdmPwdExpirationTime can be used to determine if LAPS is in use from any authenticated user.
# ref https://adsecurity.org/?p=3164
COMPUTER_ATTRIBUTES=['name', 'dNSHostName', 'whenCreated', 'operatingSystem',
                     'operatingSystemServicePack', 'lastLogon', 'logonCount',
                     'operatingSystemHotfix', 'operatingSystemVersion',
                     'location', 'managedBy', 'description', 'ms-Mcs-AdmPwd', 'mcs-AdmPwdExpirationTime']

USER_ATTRIBUTES=[
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
        'nTSecurityDescriptor',
    ]

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
    return conn.search(search_base, simple_filter, attributes=attributes, paged_size=MAX_PAGE_SIZE)

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
        response = conn.search(search_base, f, attributes=attributes)
        if conn.result['result'] == 4:
            # reached max results
            if cs.index(l) == cs.index(r) + 1:
                logger.debug('Failed to limit results. Moving on')
                results.extend(response)
                ft = '(&{}(!(cn<={}))(cn<={}))'
                l = r
                r = cs[-1]
            else:
                r = cs[cs.index(l)+1]
        elif r == cs[-1]:
            # get any remaining 'z' results
            results.extend(response)
            conn.search(search_base, '(&{}(!(cn<=z)))'.format(simple_filter), attributes=attributes)
            results.extend(response)
            break
        else:
            results.extend(conn.response)
            ft = '(&{}(!(cn<={}))(cn<={}))'
            l = r
            r = cs[-1]
    return results


def get_users(conn, search_base, basic=False):
    ''' get all domain users '''
    attrs = list(USER_ATTRIBUTES)
    if basic:
        attrs = ['userPrincipalName', 'samAccountName', 'objectSid', 'distinguishedName', 'memberOf']
    return get_all(conn, search_base, '(objectCategory=user)', attributes=attrs)

def get_groups(conn, search_base):
    ''' get all domain groups '''
    # use domain as base to get builtin and domain groups in one query
    # alternatively, you can do 2 queries with bases:
    #    cn=users,cn=mydomain,cn=com
    #    cn=users,cn=builtins,cn=mydomain,cn=com
    results = get_all(conn, search_base, '(objectCategory=group)', ['objectSid', 'groupType'])
    return [g for g in results if g.get('dn', None)]


def get_computer(conn, search_base, hostname, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    if '.' in hostname:
        conn.search(search_base, '(&(objectCategory=computer)(dNSHostname={}))'.format(hostname), attributes=attributes)
    else:
        conn.search(search_base, '(&(objectCategory=computer)(cn={}))'.format(hostname), attributes=attributes)
    return conn.response[0]

def get_computers(conn, search_base, attributes=[], basic=False):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    if basic:
        attributes = ['dNSHostName', 'distinguishedName']
    results = get_all(conn, search_base, '(objectCategory=computer)', attributes)
    return [g for g in results if g.get('dn', None)]

def get_user_dn(conn, search_base, user):
    conn.search(search_base, '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})(samAccountName={})))'.format(user, user, user))
    return conn.response[0]['dn']

def get_user_groups(conn, search_base, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn. '''
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
    if group.find('=') > 0:
        response = conn.search(search_base, '(&(objectCategory=Group)(distinguishedName={}))'.format(group),
                    attributes=['objectSid', 'distinguishedName'])
    else:
        response = conn.search(search_base, '(&(objectCategory=Group)(cn={}))'.format(group),
                    attributes=['objectSid', 'distinguishedName'])
    if len(response) == 0:
        logger.error('Group does not exist: '+group)
        raise ValueError('Group does not exist: '+group)
    if len(response) > 1:
        logger.error('Group returned multiple results: '+group)
        raise ValueError('Group returned multiple results: '+group)
    group = response[0]
    gid = gid_from_sid(group['attributes']['objectSid'][0])
    # get all users with primaryGroupID of gid
    response = get_all(conn, search_base, '(&(objectCategory=user)(primaryGroupID={}))'.format(gid),
                       attributes=['distinguishedName', 'userPrincipalName', 'samAccountName'])

    users = [u for u in response if u.get('dn', False)]
    # get all users in group using "memberOf" attribute. primary group is not included in the "memberOf" attribute
    response = get_all(conn, search_base, '(&(objectCategory=user)(memberOf='+group['dn']+'))', attributes=['distinguishedName', 'userPrincipalName'])
    users += [u for u in response if u.get('dn', False)]
    return users


def get_user_info(conn, search_base, user):
    user_dn = get_user_dn(conn, search_base, user)
    conn.search(search_base, '(&(objectCategory=user)(distinguishedName={}))'.format(escape(user_dn)),
                attributes=list(USER_ATTRIBUTES))
    return conn.response


def get_dc_info(args, conn=None):
    if not conn:
        server = ldap3.Server(args.server, args.port)
        conn = ldap3.Connection(server, auto_bind=True, version=args.version, receive_timeout=args.timeout)
    conn.search('', '(objectClass=*)', search_scope=ldap3.BASE, dereference_aliases=ldap3.DEREF_NEVER,
                attributes=['dnsHostName', 'supportedLDAPVersion', 'rootDomainNamingContext',
                            'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality',
                            'defaultNamingContext'])
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
