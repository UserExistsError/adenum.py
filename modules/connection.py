import sys
import ssl
import ldap3
import logging
import hashlib
import getpass

from modules.config import *

logger = logging.getLogger(__name__)

class CachingConnection(ldap3.Connection):
    ''' Subclass of ldap3.Connection which uses the range attribute
    to gather all results. It will also cache searches. '''
    def __init__(self, *args, **kwargs):
        self.cache = {}
        kwargs['auto_range'] = True
        self.timeout = kwargs.get('timeout', TIMEOUT)
        del kwargs['timeout']
        ldap3.Connection.__init__(self, *args, **kwargs)
    def search(self, search_base, search_filter, search_scope=ldap3.SUBTREE, **kwargs):
        if 'attributes' not in kwargs:
            kwargs['attributes'] = []
        kwargs['time_limit'] = self.timeout
        #kwargs['paged_size'] = 1000
        #kwargs['paged_criticality'] = True

        sha1 = hashlib.new('sha1', b''.join(
            str(a).lower().encode() for a in [search_base, search_filter]+list(kwargs.values()))).digest()
        if sha1 in self.cache:
            logger.debug('CACHE HIT ({}) {} {}'.format(search_base, search_filter, search_scope))
            self.response = self.cache[sha1]['response']
            self.result = self.cache[sha1]['result']
            return
        logger.debug('SEARCH ({}) {} {}'.format(search_base, search_filter, search_scope))
        response = []
        super().search(
            search_base,
            search_filter,
            search_scope,
            **kwargs
        )
        # return only the results
        for obj in self.response:
            if obj['type'].lower() == 'searchresentry':
                for a in [a for a in obj['attributes'] if a.startswith('member;range=')]:
                    del obj['attributes'][a]
                response.append(obj)
        # try:
        #     cookie = self.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        # except KeyError:
        #     break
        # kwargs['paged_cookie'] = cookie

        self.response = response
        logger.debug('RESULT {} {}'.format(len(self.response), str(self.result)))
        self.cache[sha1] = {'response':self.response, 'result':self.result}

        if self.result['result'] == 4:
            logger.warn('Max results reached: '+str(len(self.response)))
        #     kwargs['attributes'].append('range=1000-*')
        #     self.response += self.search(search_base, search_filter, search_scope=ldap3.SUBTREE, **kwargs)
        #     return self.response

def get_connection(args, addr=None):
    username = None
    password = None
    if not args.anonymous:
        username =  args.domain+'\\'+args.username
        if args.prompt:
            args.password = getpass.getpass()
        if args.nthash:
            if len(args.password) != 32:
                print('Error: ntlm hash must be 32 hex chars')
                sys.exit()
            # ldap3 takes LM:NTLM hash then discards the LM hash so we fake the LM hash
            password = '00000000000000000000000000000000:'+args.password
        else:
            password = args.password
            logger.debug('NTHASH '+hashlib.new('md4', password.encode('utf-16-le')).hexdigest())

    # avail: PROTOCOL_SSLv23, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2
    tls_config = ldap3.Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_OPTIONAL,
                           version=ssl.PROTOCOL_TLSv1)
    server = ldap3.Server(addr or args.server, use_ssl=args.tls, port=args.port, tls=tls_config, get_info=None)
    auth = ldap3.ANONYMOUS if args.anonymous else ldap3.NTLM
    conn = CachingConnection(server, user=username, password=password, authentication=auth,
                             version=args.version, read_only=True, auto_range=True,
                             auto_bind=False, receive_timeout=args.timeout, timeout=args.timeout)

    conn.open()
    if args.starttls:
        conn.start_tls()
    conn.bind()
    return conn
