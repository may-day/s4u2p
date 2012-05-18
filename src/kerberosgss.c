/**
 * Copyright (c) 2006-2010 Apple Inc. All rights reserved.
 * Copyright (c) 2012 Norman Krämer. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

/**
 * This is a derivative work of the kerberos 1.1.1 package http://trac.calendarserver.org/
 */

#include <Python.h>
#include "kerberosgss.h"

#include "base64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min);

extern PyObject *GssException_class;
extern PyObject *KrbException_class;

int authenticate_gss_impers_step(gss_impers_state* state, const char* challenge)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    int ret = AUTH_GSS_CONTINUE;
    
    // Always clear out the old response
    if (state->response != NULL)
    {
        free(state->response);
        state->response = NULL;
    }
    
    // If there is a challenge (data from the server) we need to give it to GSS
    if (challenge && *challenge)
    {
        int len;
        input_token.value = base64_decode(challenge, &len);
        input_token.length = len;
    }
    
    // Do GSSAPI step
    maj_stat = gss_init_sec_context(&min_stat,
                                    state->delegated_creds,
                                    &state->context,
                                    state->service_principal_name,
                                    GSS_C_NO_OID,
                                    (OM_uint32)state->gss_flags,
                                    0,
                                    GSS_C_NO_CHANNEL_BINDINGS,
                                    &input_token,
                                    NULL,
                                    &output_token,
                                    NULL,
                                    NULL);
    
    if ((maj_stat != GSS_S_COMPLETE) && (maj_stat != GSS_S_CONTINUE_NEEDED))
    {
        set_gss_error(maj_stat, min_stat);
        ret = AUTH_GSS_ERROR;
        goto end;
    }
    
    ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;
    // Grab the client response to send back to the server
    if (output_token.length)
    {
        state->response = base64_encode((const unsigned char *)output_token.value, output_token.length);;
        maj_stat = gss_release_buffer(&min_stat, &output_token);
    }
    
    // Try to get the user name if we have completed all GSS operations
    if (ret == AUTH_GSS_COMPLETE)
    {
        gss_name_t gssuser = GSS_C_NO_NAME;
        maj_stat = gss_inquire_context(&min_stat, state->context, &gssuser, NULL, NULL, NULL,  NULL, NULL, NULL);
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
        
        gss_buffer_desc name_token;
        name_token.length = 0;
        maj_stat = gss_display_name(&min_stat, gssuser, &name_token, NULL);
        if (GSS_ERROR(maj_stat))
        {
            if (name_token.value)
                gss_release_buffer(&min_stat, &name_token);
            gss_release_name(&min_stat, &gssuser);
            
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }
        else
        {
            state->username = (char *)malloc(name_token.length + 1);
            strncpy(state->username, (char*) name_token.value, name_token.length);
            state->username[name_token.length] = 0;
            gss_release_buffer(&min_stat, &name_token);
            gss_release_name(&min_stat, &gssuser);
        }
    }
end:
    if (output_token.value)
        gss_release_buffer(&min_stat, &output_token);
    if (input_token.value)
        free(input_token.value);
    return ret;
}


static void set_gss_error(OM_uint32 err_maj, OM_uint32 err_min)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf_maj[512];
    char buf_min[512];
    
    do
    {
        maj_stat = gss_display_status (&min_stat,
                                       err_maj,
                                       GSS_C_GSS_CODE,
                                       GSS_C_NO_OID,
                                       &msg_ctx,
                                       &status_string);
        if (GSS_ERROR(maj_stat))
            break;
        strncpy(buf_maj, (char*) status_string.value, sizeof(buf_maj));
        gss_release_buffer(&min_stat, &status_string);

        maj_stat = gss_display_status (&min_stat,
                                       err_min,
                                       GSS_C_MECH_CODE,
                                       GSS_C_NULL_OID,
                                       &msg_ctx,
                                       &status_string);
        if (!GSS_ERROR(maj_stat))
        {
            strncpy(buf_min, (char*) status_string.value, sizeof(buf_min));
            gss_release_buffer(&min_stat, &status_string);
        }
    } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
    
    PyErr_SetObject(GssException_class, Py_BuildValue("((s:i)(s:i))", buf_maj, err_maj, buf_min, err_min));
}

int authenticate_gss_use_keytab(const char* keytab){
    OM_uint32 maj_stat, min_stat=0;
    maj_stat = krb5_gss_register_acceptor_identity(keytab);
    if (GSS_ERROR(maj_stat)) {
        set_gss_error(maj_stat, min_stat);
        return AUTH_GSS_ERROR;
    }
    return AUTH_GSS_CONTINUE;
}

static OM_uint32 ticket2self(OM_uint32 *min_stat, gss_cred_id_t client_creds, gss_cred_id_t impersonator_creds, gss_cred_id_t *delegated_creds)
{
    OM_uint32 maj_stat, tmp_min_stat;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t self_target = GSS_C_NO_NAME;
    gss_buffer_desc clienttoken, servertoken;


    maj_stat = gss_inquire_cred(min_stat, impersonator_creds, &self_target, NULL, NULL, NULL);

    if (GSS_ERROR(maj_stat)) {
        goto end;
    }

    clienttoken.value = NULL;
    clienttoken.length = 0;
    maj_stat = gss_init_sec_context(min_stat, client_creds, &initiator_context, self_target,
                                 GSS_C_NO_OID, GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                 NULL, &clienttoken, NULL, NULL);


    if (GSS_ERROR(maj_stat)) {
        goto end;
    }


    servertoken.value = NULL;
    servertoken.length = 0;
    maj_stat = gss_accept_sec_context(min_stat, &acceptor_context, impersonator_creds, &clienttoken,
                                   GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &servertoken,
                                   NULL, NULL, delegated_creds);

end:
    if (initiator_context != GSS_C_NO_CONTEXT) (void) gss_delete_sec_context(&tmp_min_stat, &initiator_context, NULL);
    if (acceptor_context != GSS_C_NO_CONTEXT)  (void) gss_delete_sec_context(&tmp_min_stat, &acceptor_context, NULL);
    (void) gss_release_buffer(&tmp_min_stat, &clienttoken);
    (void) gss_release_buffer(&tmp_min_stat, &servertoken);
    if (self_target != GSS_C_NO_NAME) (void) gss_release_name(&tmp_min_stat, &self_target);

    return maj_stat;
}

int authenticate_gss_impers_init(const char* as_user, const char* service, long int gss_flags, gss_impers_state* state){
    OM_uint32 maj_stat;
    OM_uint32 min_stat, tmp_min_stat;
    gss_buffer_desc name_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name;
    gss_cred_id_t client_creds = GSS_C_NO_CREDENTIAL, impersonator_creds = GSS_C_NO_CREDENTIAL;
    int ret = AUTH_GSS_COMPLETE;
    
    state->context = GSS_C_NO_CONTEXT;
    state->service_principal_name = GSS_C_NO_NAME;
    state->delegated_creds = GSS_C_NO_CREDENTIAL;
    state->username = NULL;
    state->response = NULL;
    state->gss_flags = gss_flags;

    // Server name may be empty which means we aren't going to create our own creds
    size_t service_len = strlen(service);
    if (service_len != 0)
    {
        name_token.length = strlen(as_user);
        name_token.value = (char *)as_user;

        maj_stat = gss_import_name(&min_stat, &name_token, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &client_name);
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }

        name_token.length = strlen(service);
        name_token.value = (char *)service;
        
        maj_stat = gss_import_name(&min_stat, &name_token, GSS_C_NT_HOSTBASED_SERVICE, &state->service_principal_name);
        
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }

        // get my credentials
        maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME,
        							GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_BOTH,
        							&impersonator_creds, NULL, NULL);
        
        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }

        // now i am about to get a ticket to myself on behalf of as_user, so mask as the user and get impersonated client creds
        maj_stat = gss_acquire_cred_impersonate_name(&min_stat, impersonator_creds, client_name,
                                                  GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                                  &client_creds, NULL, NULL);

        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }

        // now request a ticket
        maj_stat = ticket2self(&min_stat, client_creds, impersonator_creds, &state->delegated_creds);

        if (GSS_ERROR(maj_stat))
        {
            set_gss_error(maj_stat, min_stat);
            ret = AUTH_GSS_ERROR;
            goto end;
        }

        // voila, with accepting the AP_REQ ( to ourself ) we got the user's delegated creds which we can use to talk
        // to the service as the user
        // you may now proceed with authenticate_gss_impers_step
    }
    
end:
	if (client_name != GSS_C_NO_NAME) (void)gss_release_name(&tmp_min_stat, &client_name);
    if (impersonator_creds != GSS_C_NO_CREDENTIAL) (void)gss_release_cred(&tmp_min_stat, &impersonator_creds);
    if (client_creds != GSS_C_NO_CREDENTIAL) (void)gss_release_cred(&tmp_min_stat, &client_creds);
    return ret;
}

int authenticate_gss_impers_clean(gss_impers_state *state){
    OM_uint32 min_stat;
    int ret = AUTH_GSS_COMPLETE;

    if (state->context != GSS_C_NO_CONTEXT)
    	(void)  gss_delete_sec_context(&min_stat, &state->context, GSS_C_NO_BUFFER);

    if (state->service_principal_name != GSS_C_NO_NAME){
    	(void) gss_release_name(&min_stat, &state->service_principal_name);
        state->service_principal_name = GSS_C_NO_NAME;
    }

    if (state->username != NULL)
    {
        free(state->username);
        state->username = NULL;
    }
    if (state->response != NULL)
    {
        free(state->response);
        state->response = NULL;
    }

    if (state->delegated_creds != GSS_C_NO_CREDENTIAL){
    	(void) gss_release_cred(&min_stat, &state->delegated_creds);
    	state->delegated_creds = GSS_C_NO_CREDENTIAL;
    }

    return ret;

}

int authenticate_gss_impers_cleanctx(gss_impers_state *state){
    OM_uint32 min_stat;
    int ret = AUTH_GSS_COMPLETE;

    if (state->context != GSS_C_NO_CONTEXT){
        (void)gss_delete_sec_context(&min_stat, &state->context, GSS_C_NO_BUFFER);
        state->context = GSS_C_NO_CONTEXT;
    }
    if (state->username != NULL)
    {
        free(state->username);
        state->username = NULL;
    }
    if (state->response != NULL)
    {
        free(state->response);
        state->response = NULL;
    }

    return ret;

}
