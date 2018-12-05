import logging

from ad.convert import gid_from_sid

logger = logging.getLogger(__name__)

def get_all(conn, search_base):
    ''' get all domain groups '''
    response = conn.searchg(search_base, '(objectCategory=group)', attributes=['objectSid', 'groupType'])
    return [g for g in response if g.get('dn', None)]

def get_users(conn, search_base, group):
    ''' return all members of group
    TODO: recurse into member groups. for now, just treat like a user. '''
    if group.find('=') > 0:
        response = conn.searchg(
            search_base,
            '(&(objectCategory=Group)(distinguishedName={}))'.format(group),
            attributes=['objectSid', 'distinguishedName'])
    else:
        response = conn.searchg(
            search_base,
            '(&(objectCategory=Group)(cn={}))'.format(group),
            attributes=['objectSid', 'distinguishedName'])
    response = list(response)
    if len(response) == 0:
        logger.error('Group does not exist: '+group)
        raise ValueError('Group does not exist: '+group)
    if len(response) > 1:
        logger.error('Group returned multiple results: '+group)
        raise ValueError('Group returned multiple results: '+group)
    group = response[0]
    gid = gid_from_sid(group['attributes']['objectSid'][0])
    # get all users with primaryGroupID of gid
    response = conn.searchg(
        search_base,
        '(&(objectCategory=user)(primaryGroupID={}))'.format(gid),
        attributes=['distinguishedName', 'userPrincipalName', 'samAccountName'])

    users = [u for u in response if u.get('dn', False)]
    # get all users in group using "memberOf" attribute. primary group is not included in the "memberOf" attribute
    response = conn.searchg(
        search_base,
        '(&(|(objectCategory=user)(objectCategory=group))(memberOf={}))'.format(group['dn']),
        attributes=['distinguishedName', 'userPrincipalName'])
    users += [u for u in response if u.get('dn', False)]
    return users
