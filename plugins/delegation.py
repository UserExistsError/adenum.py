'''
ref: https://blogs.technet.microsoft.com/pie/2017/06/30/credential-theft-made-easy-with-kerberos-delegation/

find accounts that have kerberos delegation enabled. this allows you to impersonate users.

Example: you are running as SYSTEM on a machine whose account has insecure delegation enabled:
    $u = New-Object System.Security.Principal.WindowsIdentity("administrator@mydomain.com")
    $u.Impersonate()

TODO
https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
'''

import logging

logger = logging.getLogger(__name__)

PLUGIN_NAME='delegation'
g_parser = None


def get_parser():
    return g_parser

def handler(args, conn):
    # ref: UAC
    # https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro

    # unconstrained delegation. impersonate logged in users only. (TRUSTED_FOR_DELEGATION)
    # this typically includes all domain controllers by default.
    # aka: trust this computer for delegation to any service (kerberos only)
    results = list(conn.searchg(
        args.search_base,
        '(&(|(objectClass=computer)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))',
        attributes=['cn', 'userPrincipalName', 'samAccountName', 'userAccountControl']))
    if len(results):
        print('[Unconstrained Delegation]')
        for r in results:
            print(r['dn'])

    # constrained delegation with protocol transition (eg ntlm -> krb). means account can impersonate any user for
    # specified SPNs. (uac -> TRUSTED_TO_AUTH_FOR_DELEGATION)
    results = list(conn.searchg(
        args.search_base,
        '(&(|(objectClass=computer)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=16777216))',
        attributes=['cn', 'userPrincipalName', 'samAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo']))
    if len(results):
        print('[Constrained Delegation with Protocol Transition]')
        for r in results:
            print(r['dn'])
            for spn in r['attributes']['msDS-AllowedToDelegateTo']:
                print('    ', spn)

    # constrained delegation. for listed SPNs, this computer can act on behalf of any domain user as long as they are
    # logged in
    results = list(conn.searchg(
        args.search_base,
        '(&(|(objectClass=computer)(objectClass=user))(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=16777216)))',
        attributes=['cn', 'userPrincipalName', 'samAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo']))
    if len(results):
        print('[Constrained Delegation]')
        for r in results:
            print(r['dn'])
            for spn in r['attributes']['msDS-AllowedToDelegateTo']:
                print('    ', spn)


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='find accounts with delegation enabled')
        g_parser.set_defaults(handler=handler)
    return g_parser
