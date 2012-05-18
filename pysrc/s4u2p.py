##
# Copyright (c) 2006-2009 Apple Inc. All rights reserved.
# Copyright (c) 2012 Norman Krämer All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

#
# This is a derivative work of the kerberos 1.1.1 package http://trac.calendarserver.org/
#

"""
PyKerberos Function Description.
"""

class KrbError(Exception):
    pass

class GSSError(KrbError):
    pass

"""
GSSAPI Function Result Codes:
    
    -1 : Error
    0  : GSSAPI step continuation (only returned by 'Step' function)
    1  : GSSAPI step complete, or function return OK

"""

# Some useful result codes
AUTH_GSS_CONTINUE     = 0 
AUTH_GSS_COMPLETE     = 1 
     
# Some useful gss flags 
GSS_C_DELEG_FLAG      = 1 
GSS_C_MUTUAL_FLAG     = 2 
GSS_C_REPLAY_FLAG     = 4 
GSS_C_SEQUENCE_FLAG   = 8 
GSS_C_CONF_FLAG       = 16 
GSS_C_INTEG_FLAG      = 32 
GSS_C_ANON_FLAG       = 64 
GSS_C_PROT_READY_FLAG = 128 
GSS_C_TRANS_FLAG      = 256 
     
def authGSSKeytab(keytabfile):
    """
    Set the keytab file to use in gss operations.
    """
         
def authGSSImpersonationInit(as_user, service, gssflags=GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG):
    """
    Initializes a context for GSSAPI client-side authentication with the given service principal.
    authGSSImpersonationClean must be called after this function returns an OK result to dispose of
    the context once all GSSAPI operations are complete.

    @param as_user: a string containing the user to impersonaate 'username@REALM' or just 'username' if you have a default realm set.
    @param service: a string containing the service principal in the form 'type@fqdn'
        (e.g. 'imap@mail.apple.com').
    @param gssflags: optional integer used to set GSS flags.
        (e.g.  GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG will allow 
        for forwarding credentials to the remote host)
    @return: a tuple of (result, context) where result is the result code (see above) and
        context is an opaque value that will need to be passed to subsequent functions.
    """

def authGSSImpersonationClean(context):
    """
    Destroys the context for GSSAPI client-side authentication. After this call the context
    object is invalid and should not be used again.

    @param context: the context object returned from authGSSImpersonationInit.
    @return: a result code (see above).
    """

def authGSSImpersonationStep(context, challenge):
    """
    Processes a single GSSAPI client-side step using the supplied server data.

    @param context: the context object returned from authGSSImpersonationInit.
    @param challenge: a string containing the base64-encoded server data (which may be empty
        for the first step).
    @return: a result code (see above).
    """

def authGSSImpersonationResponse(context):
    """
    Get the client response from the last successful GSSAPI client-side step.

    @param context: the context object returned from authGSSImpersonationInit.
    @return: a string containing the base64-encoded client data to be sent to the server.
    """

def authGSSImpersonationUserName(context):
    """
    Get the user name of the principal authenticated via the now complete GSSAPI client-side operations.
    This method must only be called after authGSSImpersonationStep returns a complete response code.

    @param context:   the context object returned from authGSSImpersonationInit.
    @return: a string containing the user name.
    """

