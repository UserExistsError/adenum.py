import logging
from lib.adldap import *
from lib.convert import *
from lib.password import *

logger = logging.getLogger(__name__)

PLUGIN_NAME='policy'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    print('= Default Domain Policy =')
    pol = get_default_pwd_policy(args, conn)
    if pol:
        for k in sorted(pol.keys()):
            print('{:30s} {}'.format(k, pol[k]))
    else:
        print('Failed to retrieve default domain password policy')
    print('')
    # sort policies by precedence. precedence is used to determine which policy applies to a user
    # when multiple policies are applied to him/her
    pols = sorted(get_pwd_policy(conn, args.search_base), key=lambda p:int(p['attributes']['msDS-PasswordSettingsPrecedence'][0]))
    for a in [p['attributes'] for p in pols]:
        print('=', a['name'][0].title(), '=')
        print('MinimumPasswordLength          ', a['msDS-MinimumPasswordLength'][0])
        print('ComplexityEnabled              ', a['msDS-PasswordComplexityEnabled'][0])
        print('MinimumPasswordAge             ', interval_to_minutes(int(a['msDS-MinimumPasswordAge'][0])) // 1440)
        print('MaximumPasswordAge             ', interval_to_minutes(int(a['msDS-MaximumPasswordAge'][0])) // 1440)
        print('HistorySize                    ', a['msDS-PasswordHistoryLength'][0])
        print('LockoutThreshold               ', a['msDS-LockoutThreshold'][0])
        print('LockoutObservationWindow       ', interval_to_minutes(int(a['msDS-LockoutObservationWindow'][0])))
        print('LockoutDuration                ', interval_to_minutes(int(a['msDS-LockoutDuration'][0])))
        print('ReversibleEncryptionEnabled    ', a['msDS-PasswordReversibleEncryptionEnabled'][0])
        print('Precedence                     ', a['msDS-PasswordSettingsPrecedence'][0])
        print('Applies to')
        for dn in a['msDS-PSOAppliesTo']:
            print('\t'+dn) if args.dn else print('\t'+cn(dn))
        print('')


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='get policy info')
        g_parser.set_defaults(handler=handler)
    return g_parser
