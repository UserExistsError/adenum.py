'''
ref: https://blogs.technet.microsoft.com/pie/2017/06/30/credential-theft-made-easy-with-kerberos-delegation/

find accounts that have kerberos delegation enabled. this allows you to impersonate users.

Example: you are running as SYSTEM on a machine whose account has insecure delegation enabled:
    $u = New-Object System.Security.Principal.WindowsIdentity("administrator@mydomain.com")
    $u.Impersonate()
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

    # legacy delegation. impersonate logged in users only. (TRUSTED_FOR_DELEGATION)
    # this typically includes all domain controllers by default. not sure if this is any better than just
    # using SYSTEM access to steal/dupe a token.
    results = conn.search(
        args.search_base,
        '(&(|(objectClass=computer)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))',
        attributes=['cn', 'userPrincipalName', 'samAccountName', 'userAccountControl'])
    if len(results):
        print('[Legacy Delegation]')
        for r in results:
            print(r['dn'])

    # protocol transition (eg krb -> ntlm). means account can impersonate any user. (TRUSTED_TO_AUTH_FOR_DELEGATION)
    results = conn.search(
        args.search_base,
        '(&(|(objectClass=computer)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=16777216))',
        attributes=['cn', 'userPrincipalName', 'samAccountName', 'userAccountControl'])
    if len(results):
        print('[Legacy Delegation with Protocol Transition]')
        for r in results:
            print(r['dn'])

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='find accounts with insecure kerberos delegation enabled')
        g_parser.set_defaults(handler=handler)
    return g_parser
