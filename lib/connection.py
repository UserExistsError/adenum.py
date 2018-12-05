import sys
import ssl
import time
import pickle
import ldap3
import logging
import hashlib
import getpass
import sqlite3
import threading

from lib.config import TIMEOUT, MAX_PAGE_SIZE

logger = logging.getLogger(__name__)


class CachingConnection(ldap3.Connection):
    ''' Subclass of ldap3.Connection which will cache searches.
    TODO: super class to handle per thread connections. some thread safety issues in here
    '''
    # used for per thread database connections
    local = threading.local()

    def __init__(self, *args, **kwargs):
        # metrics
        self.query_count = 0
        self.cache_hits = 0

        # if session file given, save query results
        self.session_file = ''  # empty string creates db using a temporary file
        if 'session' in kwargs:
            self.session_file = kwargs['session']
            del kwargs['session']

        # timeout is not a valid arg for parent
        self.timeout = kwargs.get('timeout', TIMEOUT)
        del kwargs['timeout']
        self.server_fqdn = kwargs.get('server_fqdn', args[0].host).lower()
        del kwargs['server_fqdn']
        ldap3.Connection.__init__(self, *args, **kwargs)

    def get_conn(self):
        # return thread specific db connection
        if not getattr(self.local, 'conn', None) or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.session_file)
        return self.local.conn

    class SearchResponse:
        ''' query response object. returns generator with 1 result per call '''
        def __init__(self, conn, key, page_size=MAX_PAGE_SIZE):
            self.conn = conn
            self.key = key
            self.page_size = page_size
        def __iter__(self):
            self.pageno = 0
            self.page = []
            return self
        def __next__(self):
            if len(self.page) == 0:
                cur = self.conn.execute('SELECT result FROM {} ORDER BY rowid LIMIT ? OFFSET ?'.format(self.key),
                                        (self.page_size, self.page_size * self.pageno))
                self.page = cur.fetchall()
                if len(self.page) == 0:
                    raise StopIteration
                logger.debug('SELECT result FROM {} LIMIT {} OFFSET {}'.format(
                    self.key, self.page_size, self.page_size * self.pageno))
                self.pageno += 1
            return pickle.loads(self.page.pop(0)[0])

    def cache_append(self, key, response, query, pageno):
        ''' add each response to the cache as a row in the db '''
        conn = self.get_conn()
        with conn:
            conn.execute('CREATE TABLE IF NOT EXISTS cache_meta (key TEXT, time INTEGER, server TEXT, query TEXT, user TEXT)')
            conn.execute('INSERT OR REPLACE INTO cache_meta (key, time, server, query, user) VALUES (?, ?, ?, ?, ?)',
                         (key, int(time.time()), self.server_fqdn, query, self.extend.standard.who_am_i().split(':')[-1]))
            conn.execute('CREATE TABLE IF NOT EXISTS {} (result BLOB)'.format(key))
            for r in response:
                conn.execute('INSERT INTO {} (result) VALUES (?)'.format(key), (pickle.dumps(r),))

    def get_key(self, search_base, search_filter, search_scope, kwargs):
        # add host/user/controls into key, too?
        key_params = [search_base, search_filter, search_scope]
        key_params.extend(sorted(map(str.lower, kwargs.get('attributes', []))))
        key = hashlib.new('sha1', b'\x00'.join([str(a).lower().encode() for a in key_params])).hexdigest().upper()
        return 'h' + key

    def cache_get(self, key):
        conn = self.get_conn()
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='{}'".format(key))
        exists = (cur.fetchone() is not None)
        if exists:
            return self.SearchResponse(conn, key)
        return None

    def searchg(self, search_base, search_filter, search_scope=ldap3.SUBTREE, **kwargs):
        if 'attributes' not in kwargs:
            kwargs['attributes'] = []

        query = 'base=({}) filter={} scope={}'.format(search_base, search_filter, search_scope)
        key = self.get_key(search_base, search_filter, search_scope, kwargs)
        resp = self.cache_get(key)
        if resp:
            logger.debug('CACHE HIT: {}'.format(search_filter))
            self.cache_hits += 1
            return resp

        logger.debug('SEARCH ({}) {} {}'.format(search_base, search_filter, search_scope))
        kwargs['paged_criticality'] = True # fail if paging not supported
        kwargs['time_limit'] = self.timeout

        pageno = 0
        while True:
            super().search(search_base, search_filter, search_scope, **kwargs)
            result = dict(self.result)
            self.query_count += 1

            # remove response metadata
            response = []
            for obj in self.response:
                if obj['type'].lower() == 'searchresentry':
                    for a in [a for a in obj['attributes'] if a.startswith('member;range=')]:
                        del obj['attributes'][a]
                    response.append(obj)

            # add results to cache
            self.cache_append(key, response, query, pageno)
            logger.debug('Page {}: {} results'.format(pageno, len(response)))

            # break if not doing paged search
            if 'paged_size' not in kwargs:
                break

            cookie = result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            if not cookie:
                # b'' -> last page
                break
            kwargs['paged_cookie'] = cookie
            pageno += 1

        logger.debug('RESULT {} {}'.format(len(response), str(result)))

        if result['result'] == 4:
            logger.warn('Max results reached: {}'.format(len(response)))

        return self.cache_get(key)

    def is_paged(self):
        info = self.get_info()
        return 'MaxPageSize' in info['supportedLDAPPolicies']

    def get_info(self):
        # add hostname to prevent cached result from another host
        response = self.searchg('', '(objectClass=*)', search_scope=ldap3.BASE, dereference_aliases=ldap3.DEREF_NEVER,
                                attributes=['dnsHostName', 'supportedLDAPVersion', 'rootDomainNamingContext',
                                            'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality',
                                            'defaultNamingContext', 'supportedLDAPPolicies', self.server_fqdn])
        self.info = list(response)[0]['attributes']
        return dict(self.info)


def get_connection(args, addr=None, conn_class=CachingConnection):
    username = None
    password = None
    if not args.anonymous:
        username =  args.domain+'\\'+args.username
        if args.password is None:
            args.password = getpass.getpass()
        if args.nthash:
            if len(args.password) != 32:
                logger.error('Error: ntlm hash must be 32 hex chars')
                sys.exit()
            # ldap3 takes LM:NTLM hash then discards the LM hash so we fake the LM hash
            password = '00000000000000000000000000000000:'+args.password
        else:
            password = args.password
            logger.debug('NTHASH '+hashlib.new('md4', password.encode('utf-16-le')).hexdigest())

    # avail: PROTOCOL_SSLv23, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2
    tls_config = ldap3.Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_OPTIONAL,
                           version=ssl.PROTOCOL_TLSv1)
    server = ldap3.Server(addr or args.server, use_ssl=args.tls, port=args.port, tls=tls_config, get_info=ldap3.ALL if args.info else None)
    auth = ldap3.ANONYMOUS if args.anonymous else ldap3.NTLM
    conn = conn_class(server, user=username, password=password, authentication=auth,
                      version=args.version, read_only=True, auto_range=True,
                      auto_bind=False, receive_timeout=args.timeout, timeout=args.timeout,
                      session=args.session, server_fqdn=args.server_fqdn,
                      #sasl_mechanism=ldap3.KERBEROS, sasl_credentials=(args.server_fqdn,) # for kerberos
    )
    conn.open()
    if args.info:
        print(server.info)
    if args.starttls:
        conn.start_tls()
    conn.bind()
    return conn
