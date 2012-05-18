from s4u2p import *
import httplib
import argparse

parser = argparse.ArgumentParser(description="A small example program to show usage of the services for user kerberos extension.")
parser.add_argument("--user", dest="user", help="user to impersonate", default="kraemer")
parser.add_argument("--host", dest="host", help="host, where a webserver is running", default="VM-WIN7-KRAEMER")
parser.add_argument("--port", dest="port", help="port, where a webserver is listening", default=80, type=int)
parser.add_argument("--servicename", dest="servicename", help="service with which a kerberos session is to be initiated.", default="http@VM-WIN7-KRAEMER")
parser.add_argument("--path", dest="path", help="path to kerberos protected resource on the webserver", default="/username/") # my sample webpage just replies with: Hello <domainuser>
parser.add_argument("--keytab", dest="keytab", help="path to keytab if you won't use system's default one", default=None)


def getConn(host, port):
    h = httplib.HTTPConnection(host, port)
    h.connect()
    return h
    
def callserver(h, path, ctx, step, response):

    neg=False
    # Setup Headers
    h.putrequest('GET', path)
    
    h.endheaders()

    # Make http call
    resp = h.getresponse()
    if resp.status == 401 and resp.getheader("WWW-Authenticate") in ("Negotiate"):
        count=0
        neg=True
        status=AUTH_GSS_CONTINUE
	while count<10 and status==AUTH_GSS_CONTINUE:
	
	    if resp.status == 401: resp.read() # read before attempt to make new request
	    #print "count", count
	    count = count+1
	    servertoken=(resp.getheader("WWW-Authenticate").split(" ") + [""])[1]
	    if servertoken == "" and count > 1:
	      # we'd need a servertoken after we send our sessionticket
	      print "breaking"
	      break
	      
    	    status = step(ctx, servertoken)
    	    if status == AUTH_GSS_CONTINUE or (status == AUTH_GSS_COMPLETE and count==1): # if no mutual authentication flag is set the first call to step already results in a _COMPLETE, but we still have to send our session ticket
		clienttoken = response(ctx)
	    
		h.putrequest("GET", path)
		h.putheader('Authorization', 'Negotiate %s' % clienttoken)
		h.endheaders()
		resp = h.getresponse()
	    else:
		print "status",status
	    
    if resp.status not in (200, 301):
	print "Error: %s" % str(resp.status)
    else:

	if not neg:
    	    print "No Negotiation with server (authentication reused or site unprotected)"
        print "HTTP Status: %s" % str(resp.status)
        print resp.read()
        
    return resp.status

def noImpersonationCalls(args):
   """
   A non impersonated call using the kerberos package.
   """
   
   import kerberos
   _ignore, ctx = kerberos.authGSSClientInit(args.servicename)

   h = getConn(args.host, args.port)
   callserver(h, args.path, ctx, kerberos.authGSSClientStep, kerberos.authGSSClientResponse)

   callserver(h, args.path, ctx, kerberos.authGSSClientStep, kerberos.authGSSClientResponse)
   print "username", kerberos.authGSSClientUserName(ctx)
   kerberos.authGSSClientClean(ctx) # clean up

def oneAuthMultipleCalls(args):
   """
   With HTTP 1.1 we can send multiple requests through the same connection, since it stays open.
   If the the backend reuses the authorization, we are queried only for the first request.
   n.b.: in IIS to enable reuse of auth set authPersistNonNTLM to true and authPersistSingleRequest to false in the windowsAuthorization for the website.
   """
   _ignore, ctx = authGSSImpersonationInit(args.user, args.servicename)

   h = getConn(args.host, args.port)
   resp=callserver(h, args.path, ctx, authGSSImpersonationStep, authGSSImpersonationResponse)
   if resp == 401:
    # maybe the user was explicitly denied
    # in any case our ctx is now in an unready state, we need to reset it
    pass
   else:
    callserver(h, args.path, ctx, authGSSImpersonationStep, authGSSImpersonationResponse)
    print "username", authGSSImpersonationUserName(ctx)
     
   authGSSImpersonationClean(ctx) # clean up


def reuseCredMultipleCalls(args):
   """
   If we were already authorized by the server but the server requests a new authorization we can reuse the delegated credentials we already created, thus avoiding an additional
   call to authGSSImpersonationInit. Of course this implies we want to connect as the same user again.
   """
   _ignore, ctx = authGSSImpersonationInit(args.user, args.servicename)
   
   h = getConn(args.host, args.port)
   callserver(h, args.path, ctx, authGSSImpersonationStep, authGSSImpersonationResponse)

   h = getConn(args.host, args.port) # creating a new connection the server requests a new authentication
  
   authGSSImpersonationCleanCtx(ctx) # keep delegated creadentials, just clean context, established username and last response from server

   callserver(h, args.path, ctx, authGSSImpersonationStep, authGSSImpersonationResponse) # in the 2nd call we don't pass the ticket
   print "username", authGSSImpersonationUserName(ctx)
   authGSSImpersonationClean(ctx) # clean up


args = parser.parse_args()

print """
URL to get        : %s:%s%s
as user           : %s
session ticket for: %s
used keyfile      : %s\n""" % (args.host,args.port, args.path, args.user, args.servicename, "default" if not args.keytab else args.keytab)

if args.keytab:
    authGSSKeytab(args.keytab)
    

print "oneAuthMultipleCalls"
oneAuthMultipleCalls(args)

#print "noImpersonationCalls"
#noImpersonationCalls(args)

print "\nreuseCredMultipleCalls"
reuseCredMultipleCalls(args)
