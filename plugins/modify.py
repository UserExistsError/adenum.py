PLUGIN_NAME='modify'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    # 'MODIFY_ADD', 'MODIFY_DELETE', 'MODIFY_INCREMENT', 'MODIFY_REPLACE'
    raise NotImplementedError
    action_map = {'add':ldap3.MODIFY_ADD, 'del':ldap3.MODIFY_DELETE, 'inc':ldap3.MODIFY_INCREMENT, 'replace':ldap3.MODIFY_REPLACE}
    conn.modify(dn, {args.attribute:[(ldap3.MODIFY_REPLACE, args.values)]})
    logger.debug(conn.result)


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='modify an object attribute')
        g_parser.set_defaults(handler=handler)
        g_parser.add_argument('action', choices=['add', 'del', 'inc', 'replace'], help='action to perform')
        g_parser.add_argument('distinguished_name', metavar='dn', help='distinguishedName')
        g_parser.add_argument('attribute', help='attribute to modify')
        g_parser.add_argument('values', nargs='*', default=[], help='value(s) to add/modify')
    return g_parser
