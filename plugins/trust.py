PLUGIN_NAME='trust'
g_parser = None

def get_parser():
    return g_parser

def trust_attributes(a):
    s = ''
    s += '(transitive={})'.format(a & 1 == 0)
    # s += '(win2k+={})'.format(a & 2 != 0)
    s += '(SID-filtering={})'.format(a & 4 != 0)
    # s += '(forest-trust={})'.format(a & 8 != 0)
    # s += '(cross-org={})'.format(a & 10 != 0)
    # s += '(forest-internal={})'.format(a & 20 != 0)
    s += '(SID-history={})'.format(a & 40 != 0)
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
    attributes=['trustAttributes', 'trustAuthIncoming', 'trustAuthOutgoing', 'trustDirection',
                'trustPartner', 'trustType']
    conn.search(args.search_base, '(objectClass=trustedDomain)', attributes=attributes)
    for r in conn.response:
        print('Partner     ', r['attributes']['trustPartner'][0])
        print('PartnerDN   ', r['dn'])
        print('Attributes  ', trust_attributes(int(r['attributes']['trustAttributes'][0])))
        #print('Direction   ', direction_map[int(r['attributes']['trustDirection'][0])])
        print('Direction   ', r['attributes']['trustPartner'][0], direction_map[int(r['attributes']['trustDirection'][0])], args.domain)
        print('Type        ', type_map[int(r['attributes']['trustType'][0])])
        print()

def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all domain trusts')
        g_parser.set_defaults(handler=handler)
    return g_parser
