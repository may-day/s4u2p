/**
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define AUTH_GSS_ERROR      -1
#define AUTH_GSS_COMPLETE    1
#define AUTH_GSS_CONTINUE    0

typedef struct {
    gss_ctx_id_t     context;
    gss_name_t       service_principal_name;
    long int 		 gss_flags;
    char*            username;
    char*            response;

    gss_cred_id_t    delegated_creds; // the cred we use to talk to the service
} gss_impers_state;

int authenticate_gss_use_keytab(const char* keytab);
int authenticate_gss_impers_init(const char* as_user, const char* service, long int gss_flags, gss_impers_state* state);
int authenticate_gss_impers_clean(gss_impers_state *state);
int authenticate_gss_impers_cleanctx(gss_impers_state *state);
int authenticate_gss_impers_step(gss_impers_state *state, const char *challenge);
