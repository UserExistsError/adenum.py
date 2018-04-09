import logging
from lib.adldap import *
from lib.convert import *
from plugins.user import print_user

logger = logging.getLogger(__name__)

PLUGIN_NAME='users'
g_parser = None

def handler(args, conn):
    if args.privileged:
        # see https://adsecurity.org/?p=3658
        priv_groups = ['domain admins', 'enterprise admins', 'account operators', 'schema admins',
                       'backup operators', 'administrators', 'DnsAdmins', 'RODC Admins']
        groups = set()
        for g in get_groups(conn, args.search_base):
            if 'admin' in g['dn'].lower() or g['dn'].split(',', maxsplit=1)[0][3:].lower() in priv_groups:
                groups.add(g['dn'])
        for g in sorted(groups):
            logger.debug('Getting users in "{}"'.format(g))
            members = get_users_in_group(conn, args.search_base, g)
            if len(members) == 0:
                continue
            print('=', g if args.dn else cn(g), '=')
            for u in members:
                if args.dn:
                    print(u['dn'])
                else:
                    try:
                        print(u['attributes']['userPrincipalName'][0].split('@')[0])
                    except:
                        print(u['attributes'].get('samAccountName', [cn(u['dn'])])[0])
            print()
            # get accounts that can replicate the DC
    else:
        users = get_users(conn, args.search_base, args.basic)
        for u in users:
            if args.basic:
                if 'dn' in u:
                    if args.dn:
                        print(u['dn'])
                    else:
                        sid = ''
                        try:
                            sid = sid_to_str(u['attributes']['objectSid'][0])
                        except:
                            pass
                        try:
                            print('{} {}'.format(u['attributes']['userPrincipalName'][0].split('@')[0], sid))
                            #print(u['attributes']['userPrincipalName'][0])
                        except:
                            name = u['attributes'].get('samAccountName', None)
                            if not name:
                                name = u['dn']
                            print('{} {}'.format(name, sid))
            else:
                print_user(u, conn, args)

def get_parser():
    return g_parser

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all users')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('-p', '--privileged', action='store_true', help='list privileged users')
        g_parser.add_argument('--basic', action='store_true', help='get basic user info')
    return g_parser
