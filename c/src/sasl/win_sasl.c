/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "proton/sasl.h"
#include "proton/sasl-plugin.h"

#include <stdlib.h>
#include <string.h>

#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)
#include <windows.h>
#include <Security.h>

#include <stdio.h>
 // SASL implementation interface
static void win_sasl_prepare(pn_transport_t *transport);
static void win_sasl_impl_free(pn_transport_t *transport);
static const char *win_sasl_impl_list_mechs(pn_transport_t *transport);

static bool win_sasl_init_server(pn_transport_t *transport);
static void win_sasl_process_init(pn_transport_t *transport, const char *mechanism, const pn_bytes_t *recv);
static void win_sasl_process_response(pn_transport_t *transport, const pn_bytes_t *recv);

static bool win_sasl_init_client(pn_transport_t *transport);
static bool win_sasl_process_mechanisms(pn_transport_t *transport, const char *mechs);
static void win_sasl_process_challenge(pn_transport_t *transport, const pn_bytes_t *recv);
static void win_sasl_process_outcome(pn_transport_t *transport);

static bool win_sasl_impl_can_encrypt(pn_transport_t *transport);
static ssize_t win_sasl_impl_max_encrypt_size(pn_transport_t *transport);
static ssize_t win_sasl_impl_encode(pn_transport_t *transport, pn_bytes_t in, pn_bytes_t *out);
static ssize_t win_sasl_impl_decode(pn_transport_t *transport, pn_bytes_t in, pn_bytes_t *out);

const pnx_sasl_implementation sasl_impl = {
    win_sasl_impl_free,
    win_sasl_impl_list_mechs,

    win_sasl_init_server,
    win_sasl_init_client,

    win_sasl_prepare,

    win_sasl_process_init,
    win_sasl_process_response,

    win_sasl_process_mechanisms,
    win_sasl_process_challenge,
    win_sasl_process_outcome,

    win_sasl_impl_can_encrypt,
    win_sasl_impl_max_encrypt_size,
    win_sasl_impl_encode,
    win_sasl_impl_decode
};

extern const pnx_sasl_implementation * const win_sasl_impl;
const pnx_sasl_implementation * const win_sasl_impl = &sasl_impl;

static const char GSSAPI[] = "GSSAPI";
static CtxtHandle    context;
static SecPkgContext_Sizes context_sizes;
static SecPkgContext_StreamSizes context_stream_sizes;
static SecBufferDesc recv_tok_desc;
static SecBuffer     recv_tok;
static CredHandle    cred;
static TimeStamp     cred_expiry;
static SecBuffer     send_tok;
static SecBufferDesc send_tok_desc;
static SECURITY_STATUS maj_stat;

void initialize_context(pn_transport_t *transport)
{
    send_tok_desc.ulVersion = SECBUFFER_VERSION;
    send_tok_desc.cBuffers = 1;
    send_tok_desc.pBuffers = &send_tok;
    send_tok.BufferType = SECBUFFER_TOKEN;
    send_tok.cbBuffer = 0;
    send_tok.pvBuffer = NULL;

    const char* c = pnx_sasl_get_principal(transport);

    ULONG attribs;        
    SECURITY_STATUS maj_stat = InitializeSecurityContext(
        &cred,
        SecIsValidHandle(&context) ? &context : NULL,
        (char*)pnx_sasl_get_principal(transport),
        ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY,
        0,
        SECURITY_NATIVE_DREP,
        recv_tok.cbBuffer ? &recv_tok_desc : NULL,
        0,
        &context,
        &send_tok_desc,
        &attribs,
        &cred_expiry
    );

    /*if (maj_stat < 0)
    {
        
    } else */
    if (maj_stat != SEC_I_CONTINUE_NEEDED)
    {
        int query_stat = QueryContextAttributes(&context, SECPKG_ATTR_SIZES, &context_sizes);
        /*if (query_stat < 0)
            check_retcode(query_stat);*/
    }    
}

void win_sasl_prepare(pn_transport_t* transport)
{
}

bool win_sasl_init_server(pn_transport_t* transport)
{
    pnx_sasl_set_desired_state(transport, SASL_POSTED_MECHANISMS);
    return true;
}

bool win_sasl_init_client(pn_transport_t* transport)
{
    DWORD len = 1024;    
    TCHAR username[1025];

    GetUserNameEx(NameUserPrincipal, username, &len);

    SecInvalidateHandle(&cred);
    SecInvalidateHandle(&context);

    maj_stat = AcquireCredentialsHandle(
        username,
        MICROSOFT_KERBEROS_NAME_A,
        SECPKG_CRED_OUTBOUND,
        NULL,
        NULL,
        NULL,
        NULL,
        &cred,
        &cred_expiry
    );
    
    recv_tok_desc.ulVersion = SECBUFFER_VERSION;
    recv_tok_desc.cBuffers = 1;
    recv_tok_desc.pBuffers = &recv_tok;
    recv_tok.BufferType = SECBUFFER_TOKEN;
    recv_tok.cbBuffer = 0;
    recv_tok.pvBuffer = NULL;
        
    pnx_sasl_set_context(transport, &context);
    return true;    
}

void win_sasl_impl_free(pn_transport_t *transport)
{    
}

bool win_sasl_process_mechanisms(pn_transport_t *transport, const char *mechs)
{

    pnx_sasl_set_selected_mechanism(transport, GSSAPI);

    pnx_sasl_set_desired_state(transport, SASL_POSTED_INIT);
    return true;
}

const char *win_sasl_impl_list_mechs(pn_transport_t *transport)
{
     return "GSSAPI";
}

void win_sasl_process_init(pn_transport_t *transport, const char *mechanism, const pn_bytes_t *recv)
{
    pnx_sasl_set_desired_state(transport, SASL_POSTED_OUTCOME);
}

void win_sasl_process_challenge(pn_transport_t *transport, const pn_bytes_t *recv)
{
    recv_tok.cbBuffer = recv->size;
    recv_tok.pvBuffer = const_cast<char *> (recv->start);        

    FreeContextBuffer(send_tok.pvBuffer);
    initialize_context(transport);
    if (send_tok.pvBuffer != 0) { // Server expects another token
        pnx_sasl_set_bytes_out(transport, pn_bytes(send_tok.cbBuffer, (const char*)send_tok.pvBuffer));
        pnx_sasl_set_desired_state(transport, SASL_POSTED_RESPONSE);
    }
}

void win_sasl_process_response(pn_transport_t *transport, const pn_bytes_t *recv)
{

}

void win_sasl_process_outcome(pn_transport_t* transport)
{

}

bool win_sasl_impl_can_encrypt(pn_transport_t *transport)
{
    return false;
}

ssize_t win_sasl_impl_max_encrypt_size(pn_transport_t *transport)
{
    return 0;
}

ssize_t win_sasl_impl_encode(pn_transport_t *transport, pn_bytes_t in, pn_bytes_t *out)
{
    return 0;
}

ssize_t win_sasl_impl_decode(pn_transport_t *transport, pn_bytes_t in, pn_bytes_t *out)
{
    return 0;
}
