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
#include <stdint.h>
#include <string.h>

#include "wish_debug.h"
#include "wish_rpc.h"

#include "mist_handler.h"
#include "mist_app_control.h"
#include "mist_app_manage.h"
#include "bson.h"
#include "bson_visit.h"
#include "utlist.h"

rpc_handler control_model_handler =           { .op = "control.model",          .handler = handle_control_model };
rpc_handler control_write_handler =           { .op = "control.write",          .handler = handle_control_write };
rpc_handler control_follow_handler =          { .op = "control.follow",         .handler = handle_control_follow};
rpc_handler control_read_handler =            { .op = "control.read",           .handler = handle_control_read };
rpc_handler control_invoke_handler =          { .op = "control.invoke",         .handler = handle_control_invoke };
rpc_handler control_map_handler =             { .op = "control.map",            .handler = handle_control_map };
rpc_handler control_request_mapping_handler = { .op = "control.requestMapping", .handler = handle_control_request_mapping };
rpc_handler control_notify_handler =          { .op = "control.notify",         .handler = handle_control_notify };
rpc_handler control_map_delete_handler =      { .op = "control.unMap",  .handler = handle_control_unmap };
rpc_handler control_signals_handler =           { .op = "control.signals",          .handler = handle_control_signals };
rpc_handler manage_claim_handler =            { .op = "manage.claim",           .handler = handle_manage_claim };
rpc_handler manage_user_ensure_handler =      { .op = "manage.user.ensure",     .handler = handle_manage_user_ensure };

void mist_device_setup_rpc_handlers(rpc_server* server) {
    /* FIXME this check below is needed because the handlers are statically
     * allocated which will not work (the linked list will fail)
     * if we have several Mist apps linked into one single
     * executable (as is the situation on an embedded system)
     */
    if (control_model_handler.next != NULL) {
        server->handlers = &control_model_handler;
        return;
    }
    rpc_server_register(server, &control_model_handler);
    rpc_server_register(server, &control_read_handler);
    rpc_server_register(server, &control_write_handler);
    rpc_server_register(server, &control_invoke_handler);
    rpc_server_register(server, &control_follow_handler);
    rpc_server_register(server, &control_map_handler);
    rpc_server_register(server, &control_request_mapping_handler);
    rpc_server_register(server, &control_map_delete_handler);
    rpc_server_register(server, &control_notify_handler);
    rpc_server_register(server, &control_signals_handler);

    rpc_server_register(server, &manage_claim_handler);
    rpc_server_register(server, &manage_user_ensure_handler);
}

void receive_device_northbound(mist_app_t* mist_app, const uint8_t* data, int data_len, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "Received to Mist device:");
    //bson_visit(bson_doc, elem_visitor);

    bson_iterator it;
    
    if ( bson_find_from_buffer(&it, data, "end") == BSON_INT ) {
        /* Special treatment needed for 'end' requests coming in to Mist app RPC server. 
         * This is entered when a request such as control.follow is explicitly cancelled by the peer.
         * Because the id is assigned by the peer, we cannot use
         * 
         * rpc_server_end(mist_app->server, bson_iterator_int(&it));
         * 
         * to cancel the request, since several peers might have assigned the same id to their requests. (See test: wish-rpc-request-cancel.js)
         * Instead, we need to cancel the request by id, and ctx (ctx is the peer in this case).
         * But, as the ctx can be altered inside mist app (when a peer copy is done for many control.* requests), we need
         * to make a "deep comparison" of the ctxen.
         */

        rpc_server_req* elm;
        rpc_server_req* tmp;
        int id_to_end = bson_iterator_int(&it);
  
        LL_FOREACH_SAFE(mist_app->server->requests, elm, tmp) {
            wish_protocol_peer_t* ctx_peer = (wish_protocol_peer_t*) elm->ctx;
            if (memcmp(peer->luid, ctx_peer->luid, WISH_ID_LEN) == 0 && memcmp(peer->ruid, ctx_peer->ruid, WISH_ID_LEN) == 0 &&
                    memcmp(peer->rhid, ctx_peer->rhid, WISH_ID_LEN) == 0 && memcmp(peer->rsid, ctx_peer->rsid, WISH_ID_LEN) == 0) {
                /* Found a request which matches this peer */
                rpc_server_req* req = elm;
                if (req->id == id_to_end) {
                    rpc_server_fin(req);
                }
            }
        }

        
        return;
    } else if ( bson_find_from_buffer(&it, data, "ack") != BSON_INT && 
        bson_find_from_buffer(&it, data, "sig") != BSON_INT && 
        bson_find_from_buffer(&it, data, "fin") != BSON_INT && 
        bson_find_from_buffer(&it, data, "err") != BSON_INT )
    {
        // fall through to checking for op
    } else {
        // This is a response, should go to the client
        rpc_client_receive(&mist_app->protocol.rpc_client, peer, data, data_len);
        return;
    }
    
    bson bs;
    bson_init_with_data(&bs, data);
    
    rpc_server_receive(mist_app->server, peer, mist_app, &bs);
}

