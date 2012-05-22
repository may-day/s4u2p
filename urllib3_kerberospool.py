# urllib3/contrib/ntlmpool.py
# Copyright 2008-2012 Andrey Petrov and contributors (see CONTRIBUTORS.txt)
#
# This module is part of urllib3 and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

"""
NTLM authenticating pool, contributed by erikcederstran

Issue #10, see: http://code.google.com/p/urllib3/issues/detail?id=10
"""

try:
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection
import logging
import kerberos as k
import s4u2p

from urllib3.connectionpool import *
from urllib3.util import get_host

def getLogger():
    log = logging.getLogger("http_kerberos_auth_handler")
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

#log = logging.getLogger(__name__)
log = getLogger()

_Default = object()

class KerberosConnectionPool(HTTPConnectionPool):
    """
    Implements an NTLM authentication version of an urllib3 connection pool
    """

    scheme = 'http'

    def __init__(self, *args, **kwargs):
        """
        authurl is a random URL on the server that is protected by NTLM.
        user is the Windows user, probably in the DOMAIN\username format.
        pw is the password for the user.
        """
        as_user=kwargs.setdefault("as_user", None)
        self.gssflags=kwargs.setdefault("gssflags", k.GSS_C_MUTUAL_FLAG|k.GSS_C_SEQUENCE_FLAG|k.GSS_C_DELEG_FLAG)
        self.spn = kwargs.setdefault("spn", None)
        del kwargs["as_user"]
        del kwargs["gssflags"]
        del kwargs["spn"]
        if as_user:
            self.gss_step = s4u2p.authGSSImpersonationStep
            self.gss_response = s4u2p.authGSSImpersonationResponse
            self.gss_clean = s4u2p.authGSSImpersonationClean
            self.gss_init = lambda *args: s4u2p.authGSSImpersonationInit(as_user, *args)
            self.GSSError = s4u2p.GSSError
        else:
            self.gss_step = k.authGSSClientStep
            self.gss_response = k.authGSSClientResponse
            self.gss_clean = k.authGSSClientClean
            self.gss_init = k.authGSSClientInit
            self.GSSError = k.GSSError
            
        super(KerberosConnectionPool, self).__init__(*args, **kwargs)
         
    def _make_request(self, conn, method, url, timeout=_Default,
                      **httplib_request_kw):
        """
        Perform a request on a given httplib connection object taken from our
        pool.
        """
        self.num_requests += 1

        if timeout is _Default:
            timeout = self.timeout

        conn.timeout = timeout # This only does anything in Py26+
        conn.request(method, url, **httplib_request_kw)

        # Set timeout
        sock = getattr(conn, 'sock', False) # AppEngine doesn't have sock attr.
        if sock:
            sock.settimeout(timeout)

        try: # Python 2.7+, use buffering of HTTP responses
            httplib_response = conn.getresponse(buffering=True)
            httplib_response = self.authenticateConnection(conn, httplib_response, method, url, **httplib_request_kw)
        except TypeError: # Python 2.6 and older
            httplib_response = conn.getresponse()

        # AppEngine doesn't have a version attr.
        http_version = getattr(conn, '_http_vsn_str', 'HTTP/?'),
        log.debug("\"%s %s %s\" %s %s" % (method, url, http_version,
                                          httplib_response.status,
                                          httplib_response.length))

        return httplib_response
    
    def authenticateConnection(self, conn, resp, method, url, **httplib_request_kw):
        if resp.status == 401 and "Negotiate" in resp.getheader("WWW-Authenticate").split(", "):
            log.debug("WWW-Authenticate requested")
            count=0
            status=k.AUTH_GSS_CONTINUE
            if self.spn is None:
                spn = "HTTP@%s" % self.host
            else:
                spn = self.spn    
            result, context = self.gss_init(spn, self.gssflags)

            if result < 1:
                log.warning("authGSSClientInit returned result %d" % result)
                return None

            log.debug("authGSSClientInit() succeeded")
            
            while count<10 and status==k.AUTH_GSS_CONTINUE:
                
                if resp.status == 401: resp.read() # read before attempt to make new request
                #print "count", count
                if count==0: servertoken=""
                else:
                  servertoken=(resp.getheader("WWW-Authenticate").split(" ") + [""])[1]
                count = count+1
                if servertoken == "" and count > 1:
                  # we'd need a servertoken after we send our sessionticket
                  print "breaking"
                  break
                      
                status = self.gss_step(context, servertoken)
                if status == k.AUTH_GSS_CONTINUE or (status == k.AUTH_GSS_COMPLETE and count==1): # if no mutual authentication flag is set the first call to step already results in a _COMPLETE, but we still have to send our session ticket
                    clienttoken = self.gss_response(context)
                    headers = httplib_request_kw.setdefault("headers", {})
                    headers['Authorization'] = 'Negotiate %s' % clienttoken
        
                    conn.request(method, url, **httplib_request_kw)
                    try: # Python 2.7+, use buffering of HTTP responses
                        resp = conn.getresponse(buffering=True)
                    except TypeError: # Python 2.6 and older
                        resp = conn.getresponse()
                    del headers['Authorization']
                else:
                    print "status",status
            if context:
                self.gss_clean(context)
                            
        return resp
    
def test(args):
    log.setLevel(logging.DEBUG)
    log.info("starting test")
    if args.keytab:
        s4u2p.authGSSKeytab(args.keytab)
    scheme, host, port = get_host(args.url)
    p = KerberosConnectionPool(host=host, port=port, as_user=args.user, spn=args.spn)
    r=p.request("GET", args.url)
    print r.data    
    

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Kerberos authentication handler for the requests package.")
    parser.add_argument("--user", dest="user", help="user to impersonate, otherwise the current kerberos principal will be used", default=None)
    parser.add_argument("--url", dest="url", help="kerberos protected site")
    parser.add_argument("--spn", dest="spn", help="spn to use, if not given HTTP@domain will be used")
    parser.add_argument("--keytab", dest="keytab", help="path to keytab if you won't use system's default one (only needed for impersonation)", default=None)
    args = parser.parse_args()
    
    test(args)
