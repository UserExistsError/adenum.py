from ad.convert import sid_to_str

PLUGIN_NAME='trust'
g_parser = None


def get_parser():
    return g_parser

def trust_attributes(a):
    # ref https://msdn.microsoft.com/en-us/library/cc223779.aspx
    s = ''
    s += '(Transitive={})'.format(a & 0x1 == 0)
    # s += '(win2k+={})'.format(a & 2 != 0)
    s += '(SID-Filtering={})'.format(a & 0x4 != 0) # quarantine
    s += '(Cross-Forest-Root={})'.format(a & 0x8 != 0) # trust is between root domains of 2 forests
    # s += '(cross-org={})'.format(a & 10 != 0)
    # s += '(SID-history={})'.format(a & 0x40 != 0) check this
    s += '(Treat-External={})'.format(a & 0x40 != 0) # SID filtering used to ensure auth from trusted domain SIDs belong to trusted domain
    s += '(Same-Forest={})'.format(a & 0x20 != 0)    # domains are in the same forest
    return s

def handler(args, conn):
    type_map = {
        1:'Downlevel',          # legacy
        2:'Uplevel',
        3:'MIT',                # non-windows
        4:'DCE',
    }
    direction_map = {
        0:'=/=',
        1:'=>',                 # incoming
        2:'<=',                 # outgoing
        3:'<=>',                # bi-directional
    }
    attributes = [
        'trustAttributes',
        'trustAuthIncoming',
        'trustAuthOutgoing',
        'trustDirection',
        'trustPartner',
        'trustType',
        'securityIdentifier'
    ]
    response = conn.searchg(
        args.search_base,
        '(objectClass=trustedDomain)',
        attributes=attributes)
    for r in response:
        print('Partner     ', r['attributes']['trustPartner'][0])
        print('PartnerDN   ', r['dn'])
        print('PartnerSID  ', sid_to_str(r['attributes']['securityIdentifier'][0]))
        print('Attributes  ', trust_attributes(int(r['attributes']['trustAttributes'][0])))
        print('Direction   ', r['attributes']['trustPartner'][0], direction_map[int(r['attributes']['trustDirection'][0])], args.server_domain)
        print('Type        ', type_map[int(r['attributes']['trustType'][0])])
        print()

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all domain trusts')
        #g_parser.add_argument('-r', '--recursive', action='store_true', help='recursively query trusts where possible')
        g_parser.set_defaults(handler=handler)
    return g_parser
