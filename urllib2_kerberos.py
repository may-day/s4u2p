# -*- coding: utf8 -*-
#!/usr/bin/python

# urllib2 with kerberos proof of concept

# Copyright 2008 Lime Nest LLC
# Copyright 2008 Lime Spot LLC
# Copyright 2012 Norman Krämer

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# this is a derivative work of urllib2_kerberos from https://bitbucket.org/tolsen/urllib2_kerberos
# It extends the original work by way to optionally pass an username to impersonate.

import re
import logging
import urllib2 as u2

import kerberos as k
import s4u2p

def getLogger():
    log = logging.getLogger("http_kerberos_auth_handler")
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

log = getLogger()

class AbstractKerberosAuthHandler(object):
    """auth handler for urllib2 that does Kerberos HTTP Negotiate Authentication
    """
    rx = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)

    def negotiate_value(self, headers):
        """checks for "Negotiate" in proper auth header
        """
        authreq = headers.get(self.auth_header, None)

        if authreq:
            log.debug("authreq: %s", authreq)
            mo = self.rx.search(authreq)
            if mo:
                return mo.group(1)
            else:
                log.debug("regex failed on: %s" % authreq)

        else:
            log.debug("%s header not found" % self.auth_header)

        return None

    def __init__(self, as_user, spn, gssflags):
        self.retried = 0
        self.context = None
        self.gssflags=gssflags
        self.spn = spn
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

    def generate_request_header(self, req, headers, neg_value):
        self.retried += 1
        log.debug("retry count: %d" % self.retried)

        if self.spn is None:
            host = req.get_host()
            log.debug("req.get_host() returned %s" % host)

            tail, sep, head = host.rpartition(':')
            domain = tail if tail else head
            spn = "HTTP@%s" % domain
        else:
            spn = self.spn    
        result, self.context = self.gss_init(spn, self.gssflags)

        if result < 1:
            log.warning("authGSSClientInit returned result %d" % result)
            return None

        log.debug("authGSSClientInit() succeeded")

        result = self.gss_step(self.context, neg_value)

        if result < 0:
            log.warning("authGSSClientStep returned result %d" % result)
            return None

        log.debug("authGSSClientStep() succeeded")

        response = self.gss_response(self.context)
        log.debug("authGSSClientResponse() succeeded")
        
        return "Negotiate %s" % response

    def authenticate_server(self, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            log.critical("mutual auth failed. No negotiate header")
            return None

        result = self.gss_step(self.context, neg_value)

        if  result < 1:
            # this is a critical security warning
            # should change to a raise --Tim
            log.critical("mutual auth failed: authGSSClientStep returned result %d" % result)
            pass

    def clean_context(self):
        if self.context is not None:
            log.debug("cleaning context")
            self.gss_clean(self.context)
            self.context = None

    def http_error_auth_reqed(self, host, req, headers):
        neg_value = self.negotiate_value(headers) #Check for auth_header
        if neg_value is not None:
            if not self.retried > 0:
                return self.retry_http_kerberos_auth(req, headers, neg_value)
            else:
                return None
        else:
            self.retried = 0

    def retry_http_kerberos_auth(self, req, headers, neg_value):
        try:
            neg_hdr = self.generate_request_header(req, headers, neg_value)

            if neg_hdr is None:
                log.debug("neg_hdr was None")
                return None

            req.add_unredirected_header(self.authz_header, neg_hdr)
            resp = self.parent.open(req)

            if self.gssflags & k.GSS_C_MUTUAL_FLAG:
                self.authenticate_server(resp.info())

            return resp

        except self.GSSError, e:
            log.critical("GSSAPI Error: %s/%s" % (e[0][0], e[1][0]))
            return None

        finally:
            self.clean_context()
            self.retried = 0

class ProxyKerberosAuthHandler(u2.BaseHandler, AbstractKerberosAuthHandler):
    """Kerberos Negotiation handler for HTTP proxy auth
    """

    authz_header = 'Proxy-Authorization'
    auth_header = 'proxy-authenticate'

    handler_order = 480 # before Digest auth

    def __init__(self, as_user=None, spn=None, gssflags=k.GSS_C_MUTUAL_FLAG|k.GSS_C_SEQUENCE_FLAG):
        super(ProxyKerberosAuthHandler, self).__init__(as_user, spn, gssflags)
        
    def http_error_407(self, req, fp, code, msg, headers):
        log.debug("inside http_error_407")
        host = req.get_host()
        retry = self.http_error_auth_reqed(host, req, headers)
        self.retried = 0
        return retry

class HTTPKerberosAuthHandler(u2.BaseHandler, AbstractKerberosAuthHandler):
    """Kerberos Negotiation handler for HTTP auth
    """

    authz_header = 'Authorization'
    auth_header = 'www-authenticate'

    handler_order = 480 # before Digest auth

    def __init__(self, as_user=None, spn=None, gssflags=k.GSS_C_MUTUAL_FLAG|k.GSS_C_SEQUENCE_FLAG):
        super(HTTPKerberosAuthHandler, self).__init__(as_user, spn, gssflags)
        
    def http_error_401(self, req, fp, code, msg, headers):
        log.debug("inside http_error_401")
        host = req.get_host()
        retry = self.http_error_auth_reqed(host, req, headers)
        self.retried = 0
        return retry

def test(args):
    if args.keytab:
	s4u2p.authGSSKeytab(args.keytab)
    log.setLevel(logging.DEBUG)
    log.info("starting test")
    opener = u2.build_opener()
    opener.add_handler(HTTPKerberosAuthHandler(as_user=args.user))
    req=u2.Request(url=args.url)
    req2=u2.Request(url=args.url)
    resp = opener.open(req)
    print dir(resp), resp.info(), resp.code
    print resp.read()

    resp = opener.open(req2)
    print dir(resp), resp.info(), resp.code
    print resp.read()
    

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="kerberos authentication handler for urllib2.")
    parser.add_argument("--user", dest="user", help="user to impersonate", default=None)
    parser.add_argument("--url", dest="url", help="kerberos protected site")
    parser.add_argument("--keytab", dest="keytab", help="path to keytab if you won't use system's default one", default=None)
    args = parser.parse_args()
    
    test(args)

