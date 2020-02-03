/**
 * Copyright (C) 2020, ControlThings Oy Ab
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
#include "mist_app_manage.h"
#include "mist_app.h"
#include "bson_visit.h"
#include "wish_port_config.h"
#include "wish_debug.h"
#include "string.h"

/**
 * @deprecated{manage.claim is deprecated, instead the MistConfig app has a special invocable endpoint that is used for claiming a device.}
 */
void handle_manage_claim(rpc_server_req *req, const uint8_t* args) {
    int buffer_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buffer[buffer_len];

    WISHDEBUG(LOG_CRITICAL, "MistApp: manage.claim() called");
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_string(&bs, "msg", "manage.claim has been deprecated.");
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, (uint8_t *) bson_data(&bs), bson_size(&bs));
}

static void handle_manage_user_ensure_end(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "handle_manage_user_ensure_end: %p", req);

    /* Free the peer copy that we allocated in handle_manage_user_ensure. */
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_manage_user_ensure_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
    //WISHDEBUG(LOG_CRITICAL, "response to identity_import request: wish_app_core %i", payload_len);
    //bson_visit("response to identity_import", payload);
    
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "err");
    
    if (bson_iterator_type(&it) == BSON_INT) {
        // it's an error
        
        bson_iterator_from_buffer(&it, payload);
        bson_find_fieldpath_value("data.code", &it);
        if (bson_iterator_type(&it) == BSON_INT) {
            int code = bson_iterator_int(&it);
            if (code == 202) {
                // it's ok the identity was already known. Just fall through.
            } else {
                // there was some unexpexted error
                bson_iterator_from_buffer(&it, payload);
                bson_find_fieldpath_value("data.msg", &it);
                if (bson_iterator_type(&it) == BSON_STRING) {
                    WISHDEBUG(LOG_CRITICAL, "Unexpected error from identity.import, code: %i: %s", code, bson_iterator_string(&it));
                } else {
                    WISHDEBUG(LOG_CRITICAL, "Unexpected error (without msg) from identity.import code: %i", bson_iterator_int(&it));
                }
                rpc_server_error_msg(req->cb_context, code, "Unexpected error from identity.import");
                return;
            }
        } else {
            // error without code?!
            bson_visit("Totally unexpected error from identity.import code:", payload);
            rpc_server_error_msg(req->cb_context, 999, "Totally unexpected error from identity.import");
            return;
        }
    }

    //WISHDEBUG(LOG_CRITICAL, "Now to respond... %p %p", ctx, req->cb_context);
    
    int buffer_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buffer[buffer_len];

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req->cb_context, (uint8_t *) bson_data(&bs), bson_size(&bs));
}

void handle_manage_user_ensure(rpc_server_req *req, const uint8_t* args) {
    mist_app_t* mist_app = req->context;
    wish_protocol_peer_t* peer = req->ctx;

    /* We must make a heap-allocated copy of the peer, and replace req->peer with the copy.
     * We have to do this because the peer supplied in 'req' is allocated from the stack, and
     * the response to the server req will be sent asynchronously when handle_manage_claim_cb gets executed.
     * Note that we in this case we are responsible for freeing the peer copy, this is done by registering a 'end handler' for the request. 
     */   
    wish_protocol_peer_t* peer_heap = wish_platform_malloc(sizeof(wish_protocol_peer_t));
    memcpy(peer_heap, peer, sizeof(wish_protocol_peer_t));
    req->ctx = peer_heap;

    req->end = handle_manage_user_ensure_end;
    
    int buffer_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buffer[buffer_len];

    //WISHDEBUG(LOG_CRITICAL, "MistApp: manage.user.ensure() called with following args: (original req pointer: %p)", req);
    //bson_visit("MistApp: manage.user.ensure()", args);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    /*
    if (bson_iterator_type(&it) == BSON_BINDATA) {
        bson_visit("   identity to ensure:", (uint8_t*)bson_iterator_bin_data(&it));
    }
    */

    bson bs; 
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "op", "identity.import");
    bson_append_start_array(&bs, "args");
    bson_append_binary(&bs, "0", bson_iterator_bin_data(&it), bson_iterator_bin_len(&it));
    bson_append_binary(&bs, "1", peer->luid, WISH_UID_LEN);
    bson_append_string(&bs, "2", "binary");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", 0);
    bson_finish(&bs);

    //bson_visit("manage user ensure request args for core:", buffer);
    
    wish_app_request(mist_app->app, &bs, handle_manage_user_ensure_cb, req);
}
