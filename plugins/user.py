import logging
from modules.adldap import *
from modules.convert import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='user'
g_parser = None


def get_parser():
    return g_parser

def handler(args, conn):
    for u in [get_user_info(conn, args.search_base, user)[0] for user in args.users]:
        if not u.get('attributes'):
            continue
        a = u['attributes']
        # https://msdn.microsoft.com/en-us/library/ms680832.aspx
        try:
            print('UserName                 ', a.get('samAccountName', None)[0] or \
                  a.get('userPrincipalName')[0].split('@')[0])
        except:
            print('UserName                 ', cn(u['dn']))
        print('FullName                 ', get_attr(a, 'givenName', ''), get_attr(a, 'middleName', ''))
        print('DistinguishedName        ', a['distinguishedName'][0])
        print('UserPrincipalName        ', get_attr(a, 'userPrincipalName', ''))
        print('Comment                  ', ','.join(a['description']))
        print('UserComment              ', ','.join(a['info']))
        print('DisplayName              ', ' '.join(a['displayName']))
        print('E-mail                   ', ' '.join(a['mail']))
        print('JobTitle                 ', ' '.join(a['title']))

        try:
            print('AccountCreated           ', gt_to_str(a['whenCreated'][0]))
            print('AccountExpires           ', timestr_or_never(int(a['accountExpires'][0])))
            print('AccountActive            ', 'No' if int(a['userAccountControl'][0]) & 0x2 else 'Yes')
            print('AccountLocked            ', 'Yes' if int(a['lockoutTime'][0]) else 'No')
        except:
            pass

        try:
            if len(a['lockoutTime']) == 0 or int(a['lockoutTime'][0]) == 0:
                print('LockoutTime              ', '0')
            else:
                print('LockoutTime              ', timestr_or_never(int(a['lockoutTime'][0])))
            #print('LockoutDuration          ', timestr_or_never(int(a['lockoutDuration'][0])))
            print('LastLogon                ', timestr_or_never(int(a['lastLogon'][0])))

            print('FailedLogins             ', a['badPwdCount'][0])
            print('LogonCount               ', a['logonCount'][0])
            print('LastFailedLogin          ', timestr_or_never(int(a['badPasswordTime'][0])))
        except:
            pass

        try:
            # http://support.microsoft.com/kb/305144
            print('PasswordLastSet          ', timestr_or_never(int(a['pwdLastSet'][0])))
            print('PasswordExpires          ', 'No' if int(a['userAccountControl'][0]) & 0x10000 else 'Yes')
            print('UserMayChangePassword    ', 'No' if int(a['userAccountControl'][0]) & 0x40 else 'Yes')
        except:
            pass

        try:
            groups = get_user_groups(conn, args.search_base, u['dn'])
            primary_group = [g['dn'] for g in groups if struct.unpack(
                '<H', g['attributes']['objectSid'][0][-4:-2])[0] == int(a['primaryGroupID'][0])][0]
            print('PrimaryGroup              "{}"'.format(primary_group if args.dn else cn(primary_group)))
            # group scopes: https://technet.microsoft.com/en-us/library/cc755692.aspx
            # http://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/
            for g in groups:
                logger.debug(hex(dw(int(g['attributes']['groupType'][0]))) + ' ' + cn(g['dn']))
            domain_local_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & 0x4]
            global_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & 0x2]
            universal_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & 0x8]
            print('DomainLocalGroups        ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), domain_local_groups)))
            print('GlobalGroups             ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), global_groups)))
            print('UniversalGroups          ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), universal_groups)))
        except:
            pass
        print('')


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='get user info')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('users', nargs='+', help='users to search')
    return g_parser


