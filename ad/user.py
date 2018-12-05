import logging

import ad.group
from .convert import gid_from_sid

logger = logging.getLogger(__name__)

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

def get_all(conn, search_base, active_only=False):
    ''' get all domain users '''
    attrs = list(USER_ATTRIBUTES)
    filt = '(objectCategory=user)'
    if active_only:
        filt = '(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    return conn.searchg(search_base, filt, attributes=attrs)

def get_dn(conn, search_base, user):
    response = conn.searchg(
        search_base,
        '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})(samAccountName={})))'.format(user, user, user))
    return list(response)[0]['dn']

def get_info(conn, search_base, user):
    user_dn = get_dn(conn, search_base, user)
    return conn.searchg(
        search_base,
        '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn),
        attributes=list(USER_ATTRIBUTES)
    )

def get_groups(conn, search_base, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn. '''
    response = list(conn.searchg(
        search_base,
        '(&(objectCategory=User)(distinguishedName='+user+'))',
        attributes=['memberOf', 'primaryGroupID']))
    group_dns = response[0]['attributes']['memberOf']

    # get primary group which is not included in the memberOf attribute
    pgid = int(response[0]['attributes']['primaryGroupID'][0])
    groups = list(ad.group.get_all(conn, search_base))
    for g in groups:
        # Builtin group SIDs are returned as str's, not bytes
        if type(g['attributes']['objectSid'][0]) == str:
            g['attributes']['objectSid'][0] = g['attributes']['objectSid'][0].encode()
    gids = [gid_from_sid(g['attributes']['objectSid'][0]) for g in groups]
    group_dns.append(groups[gids.index(pgid)]['dn'])
    group_dns = list(map(str.lower, group_dns))
    return [g for g in groups if g['dn'].lower() in group_dns]
