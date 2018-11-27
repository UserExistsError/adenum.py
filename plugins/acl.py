import logging
from lib.adldap import *
from lib.convert import *
from lib.security import SecurityDescriptor

logger = logging.getLogger(__name__)

PLUGIN_NAME='acl'
g_parser = None

def get_class_default_security_descriptor(conn, obj_category):
    response = conn.search(
        obj_category,
        '(objectClass=classSchema)',
        search_scope=ldap3.BASE,
        attributes=['nTSecurityDescriptor', 'defaultSecurityDescriptor'])
    return response[0]['attributes']['defaultSecurityDescriptor'][0]

def get_parent_security_descriptor(conn, dn):
    ''' get objects inherited security attributes '''
    parent_dn = dn.split(',', maxsplit=1)[1]
    response = conn.search(parent_dn, '(objectClass=*)', search_scope=ldap3.BASE,
                           attributes=['nTSecurityDescriptor', 'defaultSecurityDescriptor'])
    sd = response[0]['attributes']['nTSecurityDescriptor']
    return sd[0] if len(sd) else None

def get_security_descriptor(conn, dn):
    '''
    https://docs.microsoft.com/en-us/windows/desktop/AD/how-security-descriptors-are-set-on-new-directory-objects
    '''
    response = conn.search(dn, '(objectClass=*)', search_scope=ldap3.BASE,
                           attributes=['nTSecurityDescriptor', 'defaultSecurityDescriptor',
                                       'objectClass', 'objectCategory'])
    if len(response[0]['attributes']['nTSecurityDescriptor']):
        logger.debug('Object has a defined security descriptor: '+dn)
        return response[0]['attributes']['nTSecurityDescriptor'][0]

    parent_sd = get_parent_security_descriptor(conn, dn)
    if parent_sd:
        logger.debug('Object parent has a defined security descriptor: '+dn)
        return parent_sd

    logger.debug('Object class has a default security descriptor: '+dn)
    return get_class_default_security_descriptor(conn, response[0]['attributes']['objectCategory'][0])

def handler(args, conn):
    print('[!!WARNING!!] This acl functionality is still under development')
    sd = SecurityDescriptor(get_security_descriptor(conn, args.dn[0]))
    print(sd.dump())

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='get ACL for an object')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('dn', nargs='+', help='lookup distinguished name')
    return g_parser
