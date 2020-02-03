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
#include "mist_api.h"
#include "mist_app.h"
#include "wish_app.h"
#include "wish_rpc.h"
#include "wish_protocol.h"
#include "wish_platform.h"
#include "sandbox.h"
#include "utlist.h"
#include "wish_fs.h"
#include "mist_api_sandbox.h"

#include "wish_debug.h"
#include "bson_visit.h"
#include <string.h>
#include "version.h"
#include "mist_api_persistence.h"
#include "mist_api_commission_handlers.h"

/* Static function prototypes */
static void clean_up_peers_db(mist_api_t *mist_api);

/* Global variables */
static int id = 1000;

static mist_api_t* mist_apis = NULL;

static void methods(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    rpc_handler* h = mist_api->server->handlers;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    while (h != NULL) {
        bson_append_start_object(&bs, h->op);
        bson_append_finish_object(&bs);

        h = h->next;
    }
    
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

static void version(rpc_server_req* req, const uint8_t* args) {
    
    bson bs; 
    bson_init(&bs);
    bson_append_string(&bs, "data", MIST_API_VERSION_STRING);
    bson_finish(&bs);
    
    rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

static void model_cb(rpc_client_req* req, void *ctx, uint8_t *payload, size_t payload_len) {
    bson_visit("model response:", payload);
}

static void mist_ready(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    WISHDEBUG(LOG_DEBUG, "Handling ready request!");
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_bool(&bs, "data", mist_api->wish_app->ready_state);
    bson_finish(&bs);

    //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void mist_api_update_peer_cache(mist_api_t* mist_api, wish_protocol_peer_t* peer) {
    peers_list* peers;
    bool found = false;
    bool changed = false;
    
    LL_FOREACH(mist_api->peers_db, peers) {
        if ( memcmp(peers->peer.luid, peer->luid, 32) == 0 &&
             memcmp(peers->peer.ruid, peer->ruid, 32) == 0 &&
             memcmp(peers->peer.rhid, peer->rhid, 32) == 0 &&
             memcmp(peers->peer.rsid, peer->rsid, 32) == 0 &&
             strncmp(peers->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
        {
            found = true;
            changed = true; /* Emit change in peer status regardless if there was a change in online status or not. */
            if (peers->peer.online != peer->online) {
                peers->peer.online = peer->online;
            }
            break;
        }
    }
    
    if (!found) {
        // peer not found in cache, append it
        peers_list* pe = wish_platform_malloc(sizeof(peers_list));
        if (pe == NULL) { WISHDEBUG(LOG_CRITICAL, "Memory full! Allocating %i", sizeof(peers_list)); return; }
        memcpy(&pe->peer, peer, sizeof(wish_protocol_peer_t));
        LL_APPEND(mist_api->peers_db, pe);
        changed = true;
    }

    int buf_len = 300;
    char buf[buf_len];

    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "peers");
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    if (changed) {
        rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));
        commission_event_peers_signal(mist_api);
    }
    
    /* persist peers list now */
    mist_api_peers_db_save(mist_api);
    
    // update peers for sandboxes    
    changed = false;
    
    sandbox_t* sandbox;
    LL_FOREACH(mist_api->sandbox_db, sandbox) {
        sandbox_peers_t* elt;
        LL_FOREACH(sandbox->peers, elt) {
            if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
                 memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
                 memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
                 memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
                 strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                changed = true; /* Emit change in peer status regardless if there was a change in online status or not. */
                if (elt->peer.online != peer->online) {
                    elt->peer.online = peer->online;
                }
            }
        }
    }
    
    if (changed) {
        rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    }
}

static void online(mist_app_t* ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "online(%p): %p", ctx, peer);
    
    mist_api_t* mist_api = NULL; // find from existing mist apis based on context
    mist_api_t* elt;
    
    DL_FOREACH(mist_apis, elt) {
        if(ctx == elt->mist_app) {
            // found it!
            mist_api = elt;
            break;
        }
    }
    
    if (mist_api == NULL) {
        WISHDEBUG(LOG_CRITICAL, "online failed to determine mist_api instance, bailing!");
        return;
    }
    
    mist_api_update_peer_cache(mist_api, peer);
}

static void offline(mist_app_t* ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "offline(%p): %p", ctx, peer);
    //WISHDEBUG(LOG_CRITICAL, "offline, ruid: %x %x %x ...", peer->ruid[0], peer->ruid[1], peer->ruid[2]);
    
    mist_api_t* mist_api = NULL; // find from existing mist apis based on context
    mist_api_t* elt;
    
    DL_FOREACH(mist_apis, elt) {
        if(ctx == elt->mist_app) {
            // found it!
            mist_api = elt;
            break;
        }
    }
    
    if (mist_api == NULL) {
        WISHDEBUG(LOG_CRITICAL, "offline failed to determine mist_api instance, bailing!");
        return;
    }    

    mist_api_update_peer_cache(mist_api, peer);
    clean_up_peers_db(mist_api);
}

static void mist_passthrough_end(rpc_server_req *req) {
    //WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end, end... %p", req);
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    rpc_client* peer_client = &mist_api->mist_app->protocol.rpc_client;
    rpc_client_req* e = rpc_client_find_passthru_req(peer_client, req->id);
    if (e==NULL) {
        WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end couldn't find request based on req->id: %i", req->id);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "mist_passthrough_end north ID: %i south ID: %i (passthrough id: %i peer: %p)", req->id, e->id, e->passthru_id, e->passthru_ctx);
        // Update the send_ctx for each call to passthrough. This is required because 
        // there is not own clients for each remote peer as there "shuold" be.
        peer_client->send_ctx = e->passthru_ctx;
        
        rpc_client_end_by_id(peer_client, e->id);
    }
}

static void mist_passthrough(rpc_server_req *req, const uint8_t *args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    // Make a generic function for passing the control.* and manage.* commands to the device.

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* bson_peer = (char*)bson_iterator_value(&it);

    wish_protocol_peer_t pe;
    bool success = wish_protocol_peer_populate_from_bson(&pe, bson_peer);
    
    if (!success) { bson_visit("Failed getting peer from", bson_peer); return; }
    
    wish_protocol_peer_t* peer = mist_api_peer_find(mist_api, &pe);
    
    //WISHDEBUG(LOG_CRITICAL, "Here is the peer %p", peer);
    //bson_visit("mist_passthrough", args);
    
    if(peer == NULL) {
        rpc_server_error_msg(req, 55, "Peer not found.");
        return;
    }
    
    // create a bson request with:
    //
    // { op: (copy parent op),
    //   args: [parent args splice(1)] 
    //   id: copy parent id }
    //
    // Then send to passthrough
    
    int buf_len = 700;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    // skip the prefix "sandbox.mist." from op string when forwarding request
    if (memcmp(req->op, "mist.", 5) == 0) {
        bson_append_string(&b, "op", req->op+5);
    } else {
        rpc_server_error_msg(req, 58, "Unrecognized mist command in passthrough. Should start with 'mist.' !");
        return;
    }
    
    
    bson_append_start_array(&b, "args");

    // Only single digit array index supported. 
    //   i.e Do not exceed 8 with the index. Rewrite indexing if you must!
    
    //   bson_find_from_buffer(&it, args, "1");
    //   bson_append_element(&b, "0", &it);
    //   bson_find_from_buffer(&it, args, "2");
    //   bson_append_element(&b, "1", &it);
    //   .
    //   .
    //   .
    
    int i;
    int args_len = 0;
    
    for(i=0; i<9; i++) {
        char src[21];
        char dst[21];
        
        BSON_NUMSTR(src, i+1);
        BSON_NUMSTR(dst, i);
        
        // read the argument
        bson_find_from_buffer(&it, args, src);
        bson_type type = bson_iterator_type(&it);

        if (type == BSON_EOO) {
            break;;
        } else {
            bson_append_element(&b, dst, &it);
        }
        
        args_len++;
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    //struct wish_rpc_context* rpc_ctx = (struct wish_rpc_context*) req->send_context;
    
    rpc_client_callback cb = req->ctx;
    
    // FIXME: this is a memory leak (clean up in mist_passthrough_end?)
    app_peer_t* app_peer = wish_platform_malloc(sizeof(app_peer_t));
    app_peer->app = mist_api->wish_app;
    app_peer->peer = peer;

    rpc_client* peer_client = &mist_api->mist_app->protocol.rpc_client;
    // Update the send_ctx for each call to passthrough. This is required because 
    // there is not own clients for each remote peer as there "should" be.
    peer_client->send_ctx = app_peer;

    req->end = mist_passthrough_end;
    
    rpc_client_req* client_req = rpc_server_passthru(req, peer_client, &b, cb);
}

// FIXME move these to mist_api or somewhere else this does not work if there are multiple mist_api:s
static int coercion_counter = 0;
static rpc_server_req *request_mapping_req;
static const uint8_t *request_mapping_args;

static void mist_coercion_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "Coercion response. %p %s", ctx, req->err ? "error" : "success");
    
    coercion_counter--;
    
    if(coercion_counter == 0) {
        // done here...
        WISHDEBUG(LOG_CRITICAL, "Coercion done. %p", ctx);
        
        mist_passthrough(request_mapping_req, request_mapping_args);
    }
}

static void mist_map_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    
}

static void mist_map(rpc_server_req* req, const uint8_t* args) {
    bson_visit("Handling map request!", args);
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    int buf_len = 300;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    wish_api_request(mist_api, &b, mist_map_cb);
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_object(&bs, "data");
    bson_append_bool(&bs, "mappingCool", true);
    bson_append_finish_object(&bs);

    bson_finish(&bs);

    //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static int mist_api_req_id = 0;

static void mist_request_mapping(rpc_server_req *req, const uint8_t *args) {
    //WISHDEBUG(LOG_CRITICAL, "Handling requestMapping request! Should do some coercion.");
    
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    coercion_counter = 0;
    request_mapping_req = req;
    request_mapping_args = args;
    
    //bson_visit("Handling requestMapping request:", args);
    
    bson_iterator dst_peer;
    bson_find_from_buffer(&dst_peer, args, "0");
    
    bson_iterator src_peer;
    bson_find_from_buffer(&src_peer, args, "1");

    bson_iterator it1;
    bson_iterator_from_buffer(&it1, args);
    
    if (bson_find_fieldpath_value("0.ruid", &it1) != BSON_BINDATA || bson_iterator_bin_len(&it1) != 32) {
        WISHDEBUG(LOG_CRITICAL, "Fail requestMapping: 0.ruid no.... %i", bson_iterator_type(&it1));
        return;
    }
    
    //bson_iterator_bin_data(&it1), 

    char* dst_export = NULL;
    int dst_export_len = 0;
    
    int i = 0;
    bool found = false;

    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        if ( mist_api->identities[i].occupied != 0 ) {
            if (memcmp(mist_api->identities[i].uid, bson_iterator_bin_data(&it1), bson_iterator_bin_len(&it1)) == 0) {
                // found the identity
                dst_export = mist_api->identities[i].export_data;
                dst_export_len = mist_api->identities[i].export_len;
                found = true;
                break;
            }
        }
    }
    
    if (!found) { rpc_server_error_msg(req, 63, "Could not find identity (1) for requestMapping coercion."); return; }

    bson_iterator it2;
    bson_iterator_from_buffer(&it2, args);
    
    if (bson_find_fieldpath_value("1.ruid", &it2) != BSON_BINDATA || bson_iterator_bin_len(&it2) != 32) {
        WISHDEBUG(LOG_CRITICAL, "Fail requestMapping: 1.ruid no.... %i", bson_iterator_type(&it2));
        return;
    }
    
    char* src_export = NULL;
    int src_export_len = 0;
    
    found = false;

    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        if ( mist_api->identities[i].occupied != 0 ) {
            if (memcmp(mist_api->identities[i].uid, bson_iterator_bin_data(&it2), bson_iterator_bin_len(&it2)) == 0) {
                // found the identity
                src_export = mist_api->identities[i].export_data;
                src_export_len = mist_api->identities[i].export_len;
                found = true;
                break;
            }
        }
    }
    
    if (!found) { rpc_server_error_msg(req, 63, "Could not find identity (2) for requestMapping coercion."); return; }
    
    int buffer_len = 500;
    uint8_t buffer[buffer_len];
    bson bs;
    
    if (dst_export != NULL) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "op", "mist.manage.user.ensure");
        bson_append_start_array(&bs, "args");
        bson_append_element(&bs, "0", &src_peer);
        bson_append_binary(&bs, "1", dst_export, dst_export_len);
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", ++mist_api_req_id);
        bson_finish(&bs);

        coercion_counter++;
        //bson_visit("RPC mist.manage.user.ensure (src_peer) with args:", bson_data(&bs));
        mist_api_request(mist_api, &bs, mist_coercion_cb);
    } else {
        WISHDEBUG(LOG_CRITICAL, "dst_export not set.", dst_export_len, src_export_len);
    }
    
    if (src_export != NULL) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_string(&bs, "op", "mist.manage.user.ensure"); 
        bson_append_start_array(&bs, "args");
        bson_append_element(&bs, "0", &dst_peer);
        bson_append_binary(&bs, "1", src_export, src_export_len);
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", ++mist_api_req_id);
        bson_finish(&bs);

        coercion_counter++;
        //bson_visit("RPC mist.manage.user.ensure (dst_peer) with args:", bson_data(&bs));
        mist_api_request(mist_api, &bs, mist_coercion_cb);
    } else {
        WISHDEBUG(LOG_CRITICAL, "src_export not set.");
    }
}

wish_protocol_peer_t* mist_api_peer_find(mist_api_t* mist_api, wish_protocol_peer_t* peer) {
    peers_list* elt;
    
    LL_FOREACH(mist_api->peers_db, elt) {
        if ( memcmp(peer->luid, elt->peer.luid, WISH_UID_LEN) == 0 && 
            memcmp(peer->ruid, elt->peer.ruid, WISH_UID_LEN) == 0 && 
            memcmp(peer->rhid, elt->peer.rhid, WISH_UID_LEN) == 0 && 
            memcmp(peer->rsid, elt->peer.rsid, WISH_UID_LEN) == 0 ) 
        {
            // Found!
            return &elt->peer;
        }
    }
    
    return NULL;
}

static void mist_list_services(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    WISHDEBUG(LOG_DEBUG, "Handling listServices request!");
    
    peers_list* elt;
    
    uint8_t buffer[MIST_RPC_REPLY_BUF_LEN];
    
    bson bs;
    bson_init_buffer(&bs, buffer, MIST_RPC_REPLY_BUF_LEN);
    bson_append_start_object(&bs, "data");
    
    
    int i = 0;
    char index[21];

    LL_FOREACH(mist_api->peers_db, elt) {
        BSON_NUMSTR(index, i++);
        bson_append_peer(&bs, index, &elt->peer);
    }
    
    bson_append_finish_object(&bs);

    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in mist_list_services");
        rpc_server_error_msg(req, 999, "BSON error in mist_list_services");
    }
    else {
        //wish_core_send_message(rpc_ctx->ctx, res_doc, bson_get_doc_len(res_doc));
        rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    }
}

static void mist_commission_add(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;

    bson_iterator it;
    
    bson b;
    bson_init_with_data(&b, args);
    
    if ( BSON_STRING != bson_find(&it, &b, "1") ) {
        rpc_server_error_msg(req, 451, "Argument 2 SSID not string.");
        return;
    }

    mist_wifi* tmp = NULL;
    
    mist_wifi* elt;
    LL_FOREACH(mist_api->wifi_db, elt) {
        if ( strncmp(elt->ssid, bson_iterator_string(&it), 33) == 0 ) {
            tmp = elt;
            tmp->timestamp = 1500;
            break;
        }
    }
    
    if (tmp == NULL) {
        tmp = wish_platform_malloc(sizeof(mist_wifi));
        
        if (tmp == NULL) {
            rpc_server_error_msg(req, 453, "Not found and memory full.");
            return;
        }
        
        memset(tmp, 0, sizeof(mist_wifi));
        
        tmp->next = NULL;
        // FIXME, don't use strdup, at least while string is unchecked!
        tmp->ssid = strdup(bson_iterator_string(&it));
        tmp->timestamp = 1500;

        LL_APPEND(mist_api->wifi_db, tmp);
    }

    // signal change in commission list
    int buf_len = 300;
    char buf[buf_len];

    bson sig;
    bson_init_buffer(&sig, buf, buf_len);
    bson_append_start_array(&sig, "data");
    bson_append_string(&sig, "0", "commission.list");
    bson_append_finish_array(&sig);
    bson_finish(&sig);

    rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&sig), bson_size(&sig));
    rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&sig), bson_size(&sig));
    
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void mist_commission_get_state(rpc_server_req *req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    WISHDEBUG(LOG_CRITICAL, "commission.getState request!");

    int buffer_len = 300;
    uint8_t buffer[buffer_len];

    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_string(&bs, "data", commission_state_to_string(mist_api->commissioning.state));
    bson_finish(&bs);

    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

static void mist_signals(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    //WISHDEBUG(LOG_CRITICAL, "mist.signals request!");

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "ok");
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit(req, bson_data(&bs), bson_size(&bs));

    if (mist_api->wish_app->ready_state) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_start_array(&bs, "data");
        bson_append_string(&bs, "0", "ready");
        bson_append_finish_array(&bs);
        bson_finish(&bs);

        rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    }    
}

static void mist_get_service_id(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.getServiceId request!");
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    uint8_t *wsid = mist_api->wish_app->wsid;
    bson bs;
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    bson_append_binary(&bs, "wsid", wsid, WISH_WSID_LEN);
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void mist_wish_identity_list(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    int buf_len = 4*1024;
    uint8_t buf[buf_len];
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_start_array(&bs, "data");
    
    int i=0;
    int c=0;
    
    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        if (mist_api->identities[i].occupied != 0) {
            char index[21];
            BSON_NUMSTR(index, c++);

            bson_append_start_object(&bs, index);
            bson_append_string(&bs, "alias", mist_api->identities[i].alias);
            bson_append_binary(&bs, "uid", mist_api->identities[i].uid, WISH_UID_LEN);
            bson_append_bool(&bs, "privkey", mist_api->identities[i].has_privkey);
            bson_append_finish_object(&bs);
        }
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void mist_wish_core(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    // create a bson request with:
    //
    // { op: (copy parent op),
    //   args: [parent args] 
    //   id: copy parent id }
    //
    // Then send to passthrough
    
    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    // skip the prefix "wish." from op string when forwarding request
    if (memcmp(req->op, "wish.", 5) == 0) {
        bson_append_string(&b, "op", req->op+5);
    } else {
        rpc_server_error_msg(req, 58, "Unrecognized wish command in passthrough. Should start with 'wish.' !");
    }
    
    // bson_append_element(bson *b, const char *name_or_null, const bson_iterator *elem) {
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, args);

    bson_append_start_array(&b, "args");
    
    char index[21];
    int i = 0;
    
    while (bson_iterator_next(&it) != BSON_EOO) {
        BSON_NUMSTR(index, i++);
        bson_append_element(&b, index, &it);
    }
    
    bson_append_finish_array(&b);

    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    //bson_visit("wish_core_rpc req", bson_data(&b));
    
    rpc_client_callback cb = req->ctx;
    
    req->end = mist_passthrough_end;
    
    rpc_client_req* client_req = rpc_server_passthru(req, &mist_api->wish_app->rpc_client, &b, cb);
}

// Mist remote node commands
static rpc_handler control_read_handler =                 { .op = "mist.control.read",               .handler = mist_passthrough };
static rpc_handler control_write_handler =                { .op = "mist.control.write",              .handler = mist_passthrough };
static rpc_handler control_invoke_handler =               { .op = "mist.control.invoke",             .handler = mist_passthrough };
static rpc_handler control_follow_handler =               { .op = "mist.control.follow",             .handler = mist_passthrough };
static rpc_handler control_model_handler =                { .op = "mist.control.model",              .handler = mist_passthrough };
static rpc_handler control_map_handler =                  { .op = "mist.control.map",                .handler = mist_passthrough };
static rpc_handler control_un_map_handler =               { .op = "mist.control.unMap",              .handler = mist_passthrough };
static rpc_handler control_notify_handler =               { .op = "mist.control.notify",             .handler = mist_passthrough };
static rpc_handler control_request_mapping_handler =      { .op = "mist.control.requestMapping",     .handler = mist_request_mapping };
static rpc_handler control_signals_handler =      { .op = "mist.control.signals",     .handler = mist_passthrough };

static rpc_handler manage_claim_handler =                 { .op = "mist.manage.claim",               .handler = mist_passthrough };
static rpc_handler manage_peers_handler =                 { .op = "mist.manage.peers",               .handler = mist_passthrough };
static rpc_handler manage_acl_model_handler =             { .op = "mist.manage.acl.model",           .handler = mist_passthrough };
static rpc_handler manage_acl_allow_handler =             { .op = "mist.manage.acl.allow",           .handler = mist_passthrough };
static rpc_handler manage_acl_remove_allow_handler =      { .op = "mist.manage.acl.removeAllow",     .handler = mist_passthrough };
static rpc_handler manage_acl_add_user_roles_handler =    { .op = "mist.manage.acl.addUserRoles",    .handler = mist_passthrough };
static rpc_handler manage_acl_remove_user_roles_handler = { .op = "mist.manage.acl.removeUserRoles", .handler = mist_passthrough };
static rpc_handler manage_acl_user_roles_handler =        { .op = "mist.manage.acl.userRoles",       .handler = mist_passthrough };
static rpc_handler manage_user_ensure_handler =           { .op = "mist.manage.user.ensure",         .handler = mist_passthrough };


// RPC enumeration
static rpc_handler methods_handler =                      { .op = "methods",                         .handler = methods };
static rpc_handler version_handler =                      { .op = "version",                         .handler = version };

// MistAPI commands
static rpc_handler mist_signals_handler =                 { .op = "signals",                         .handler = mist_signals };
static rpc_handler mist_ready_handler =                   { .op = "ready",                           .handler = mist_ready };
static rpc_handler mist_list_services_handler =           { .op = "listPeers",                       .handler = mist_list_services };
static rpc_handler mist_commission_add_handler =          { .op = "commission.add",                  .handler = mist_commission_add };
static rpc_handler mist_commission_get_state_handler =    { .op = "commission.getState",             .handler = mist_commission_get_state };
static rpc_handler mist_commission_list_handler =    { .op = "commission.list",                      .handler = mist_commission_list };
static rpc_handler mist_commission_perform_handler =    { .op = "commission.perform",                .handler = mist_commission_perform };
static rpc_handler mist_commission_select_wifi_handler =    { .op = "commission.selectWifi",         .handler = mist_commission_select_wifi };

static rpc_handler mist_sandbox_list_handler =            { .op = "sandbox.list",                    .handler = mist_sandbox_list };
static rpc_handler mist_sandbox_remove_handler =          { .op = "sandbox.remove",                  .handler = mist_sandbox_remove };
static rpc_handler mist_sandbox_list_peers_handler =      { .op = "sandbox.listPeers",               .handler = sandbox_list_peers };
static rpc_handler mist_sandbox_add_peer_handler =        { .op = "sandbox.addPeer",                 .handler = mist_sandbox_add_peer };
static rpc_handler mist_sandbox_remove_peer_handler =     { .op = "sandbox.removePeer",              .handler = mist_sandbox_remove_peer };
static rpc_handler mist_sandbox_allow_request_handler =   { .op = "sandbox.allowRequest",            .handler = mist_sandbox_allow_request };
static rpc_handler mist_sandbox_deny_request_handler =    { .op = "sandbox.denyRequest",             .handler = mist_sandbox_deny_request };
static rpc_handler mist_sandbox_emit_handler =            { .op = "sandbox.emit",                    .handler = mist_sandbox_emit };
static rpc_handler mist_get_service_id_handler =          { .op = "getServiceId",                    .handler = mist_get_service_id };

// Wish Core commands
static rpc_handler mist_wish_identity_list_handler =      { .op = "wish.identity.list",              .handler = mist_wish_identity_list };
static rpc_handler mist_wish_identity_get_handler =       { .op = "wish.identity.get",               .handler = mist_wish_core };
static rpc_handler mist_wish_connections_list_handler =   { .op = "wish.connections.list",           .handler = mist_wish_core };
static rpc_handler mist_wish_connections_request_handler ={ .op = "wish.connections.request",        .handler = mist_wish_core };
static rpc_handler mist_wish_identity_friend_request_handler =      { .op = "wish.identity.friendRequest",              .handler = mist_wish_core };

static rpc_handler mist_wish_relay_list_handler =         { .op = "wish.relay.list",                 .handler = mist_wish_core };
static rpc_handler mist_wish_relay_add_handler =          { .op = "wish.relay.add",                  .handler = mist_wish_core };
static rpc_handler mist_wish_relay_remove_handler =       { .op = "wish.relay.remove",               .handler = mist_wish_core };

//static rpc_handler mist_load_app_handler =                { .op = "loadApp",                         .handler = mist_load_app };

// sandbox interface
//
//   The sandbox interface is closely related to the regular mist-api interface, 
//   but is filtered according to permissions. 
static rpc_handler sandbox_login_handler =                { .op = "sandboxed.login",                   .handler = sandbox_login };
static rpc_handler sandbox_logout_handler =               { .op = "sandboxed.logout",                  .handler = sandbox_logout };
static rpc_handler sandbox_settings_handler =             { .op = "sandboxed.settings",                .handler = sandbox_settings };
static rpc_handler sandbox_signals_handler =              { .op = "sandboxed.signals",                 .handler = sandbox_signals };
static rpc_handler sandbox_methods_handler =              { .op = "sandboxed.methods",                 .handler = sandbox_methods };
static rpc_handler sandbox_list_peers_handler =           { .op = "sandboxed.listPeers",               .handler = sandbox_list_peers };
static rpc_handler sandbox_commission_list_handler =      { .op = "sandboxed.commission.list",         .handler = sandbox_commission_list };
static rpc_handler sandbox_commission_perform_handler =   { .op = "sandboxed.commission.perform",      .handler = sandbox_commission_perform };
static rpc_handler sandbox_commission_select_wifi_handler ={.op = "sandboxed.commission.selectWifi",   .handler = sandbox_commission_select_wifi };
static rpc_handler sandbox_control_read_handler =         { .op = "sandboxed.mist.control.read",       .handler = sandbox_passthrough };
static rpc_handler sandbox_control_write_handler =        { .op = "sandboxed.mist.control.write",      .handler = sandbox_passthrough };
static rpc_handler sandbox_control_invoke_handler =       { .op = "sandboxed.mist.control.invoke",     .handler = sandbox_passthrough };
static rpc_handler sandbox_control_follow_handler =       { .op = "sandboxed.mist.control.follow",     .handler = sandbox_passthrough };
static rpc_handler sandbox_control_model_handler =        { .op = "sandboxed.mist.control.model",      .handler = sandbox_passthrough };
static rpc_handler sandbox_wish_signals_handler =         { .op = "sandboxed.wish.signals",            .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_create_handler =      { .op = "sandboxed.wish.identity.create",    .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_get_handler =         { .op = "sandboxed.wish.identity.get",       .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_update_handler =      { .op = "sandboxed.wish.identity.update",    .handler = sandbox_wish_identity_update };
static rpc_handler sandbox_identity_permissions_handler = { .op = "sandboxed.wish.identity.permissions",.handler = sandbox_wish_identity_permissions };
static rpc_handler sandbox_identity_list_handler =        { .op = "sandboxed.wish.identity.list",      .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_export_handler =      { .op = "sandboxed.wish.identity.export",    .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_sign_handler =        { .op = "sandboxed.wish.identity.sign",      .handler = sandbox_wish_identity_sign };
static rpc_handler sandbox_identity_verify_handler =      { .op = "sandboxed.wish.identity.verify",    .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_friend_request_handler =         { .op = "sandboxed.wish.identity.friendRequest",          .handler = sandbox_wish_identity_friend_request };
static rpc_handler sandbox_identity_friend_request_list_handler =    { .op = "sandboxed.wish.identity.friendRequestList",      .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_friend_request_accept_handler =  { .op = "sandboxed.wish.identity.friendRequestAccept",    .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_friend_request_decline_handler = { .op = "sandboxed.wish.identity.friendRequestDecline",   .handler = sandbox_wish_passthru };
static rpc_handler sandbox_identity_remove_handler =      { .op = "sandboxed.wish.identity.remove",    .handler = sandbox_identity_remove };


// FIXME Move to mist_api structure
int wish_req_id = 0;

static void identity_export_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = (mist_api_t*) req->client->context;
    
    //bson_visit("Got exported identity", payload);
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, payload);
    bson_type inner_data_type = bson_find_fieldpath_value("data.data", &it);
    
    if (inner_data_type != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "data.data is not bindata as expected, but %i", inner_data_type);
        return;
    }
    
    const char *data = bson_iterator_bin_data(&it);
    int data_len = bson_iterator_bin_len(&it);
    
    //bson_visit("The inner data object (=the exported identity) is:", data);
    
    if (data_len > 512) {
        WISHDEBUG(LOG_CRITICAL, "exported document too large, bail out!\n");
        return;
    }
 
    
    //bson_visit((uint8_t*)bson_iterator_bin_data(&it), elem_visitor);
    bson_iterator ait;
    bson_find_from_buffer(&ait, data, "uid");
    
    if (bson_iterator_type(&ait) != BSON_BINDATA || bson_iterator_bin_len(&ait) != 32) {
        WISHDEBUG(LOG_CRITICAL, " exported uid not 32 bytes of bindata as expected! %i %i\n", bson_iterator_type(&ait), bson_iterator_bin_len(&ait));
        return;
    }
    
    char* uid = (char*) bson_iterator_bin_data(&ait);
    
    int i=0;
    
    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
        // if occupied but has no export data
        if (mist_api->identities[i].occupied != 0 && memcmp(mist_api->identities[i].uid, uid, 32) == 0 ) {
            //WISHDEBUG(LOG_CRITICAL, "   found uid @ %i", i);
            mist_api->identities[i].export_len = data_len;
            memcpy(mist_api->identities[i].export_data, data, data_len);
            return;
        }
    }

}

static void update_identity_export_db(mist_api_t* mist_api) {
    //WISHDEBUG(LOG_CRITICAL, "Update identity export DB.");
    int i = 0;
    
    for (i=0; i<MIST_API_MAX_UIDS; i++) {
        //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
        // if occupied but has no export data
        if ( mist_api->identities[i].occupied != 0 && mist_api->identities[i].export_occupied == 0 ) {
            //WISHDEBUG(LOG_CRITICAL, "   get export data %i", i);
            
            // request export data
            int buf_len = 500;
            char buf[buf_len];

            bson b;
            //bson_init_buffer(&b, buf, buf_len);
            bson_init_buffer(&b, buf, buf_len);
            bson_append_string(&b, "op", "identity.export");
            bson_append_start_array(&b, "args");
            bson_append_binary(&b, "0", mist_api->identities[i].uid, 32);
            bson_append_finish_array(&b);
            bson_append_int(&b, "id", ++wish_req_id);
            bson_finish(&b);

            //WISHDEBUG(LOG_CRITICAL, "sending request %i\n", wish_req_id);
            //bson_visit((uint8_t*) bson_data(&b), elem_visitor);
            
            wish_api_request(mist_api, &b, identity_export_cb);
            //return;
        }
    }
}

/**
 * This function iterates through the peers list of a mist_api, and removes any peer whose luid and ruid is no longer in the identities list of mist_api.
 * In order to function correctly, this function should be run after the mist_api identity list is updated.
 * Both luid and ruid identities must known, if not the peer is removed from list (but only if it is marked as offline).
 * 
 * @param mist_api the mist_api on which to act.
 */
static void clean_up_peers_db(mist_api_t *mist_api) {
    peers_list *elem = NULL;
    peers_list *tmp = NULL;
    
    /* Iterate through the peers list */
    LL_FOREACH_SAFE(mist_api->peers_db, elem, tmp) {
        bool ruid_known = false;
        bool luid_known = false;
        
        /* For each peer, check that we still known the remote party (ruid in identity list) */
        for (int i = 0; i < MIST_API_MAX_UIDS; i++) {
            if ( mist_api->identities[i].occupied ) { 
                if (memcmp(elem->peer.ruid, mist_api->identities[i].uid, 32) == 0) {
                    ruid_known = true;
                }
                if (memcmp(elem->peer.luid, mist_api->identities[i].uid, 32) == 0) {
                    luid_known = true;
                }
            }
        }
        
        /* If we encounter a peer, for which luid AND ruid are not known, they should be removed. */
        if ( (luid_known && ruid_known) == false ) {   
            if (!elem->peer.online) {
                /* Peer is offline, as expected */
                /*
                WISHDEBUG(LOG_CRITICAL, "clean_up_peers_db:%s%s unknown, removing peer! (luid %x %x %x... ruid: %x %x %x...)", luid_known?"":" luid", ruid_known?"":" ruid", 
                        elem->peer.luid[0], elem->peer.luid[1], elem->peer.luid[2], 
                        elem->peer.ruid[0], elem->peer.ruid[1], elem->peer.ruid[2]);
                */
                
                //  we should remove all peers from all sandboxes that have this identity as a ruid
                mist_sandbox_remove_peers_by_uid(mist_api, elem->peer.ruid);
                /* Remove the peer from peers_db */
                LL_DELETE(mist_api->peers_db, elem);
                wish_platform_free(elem);
                /* persist peers list now */
                mist_api_peers_db_save(mist_api);
            }
            else {
                /* Identity not in identity list, but still online? This is an anomaly that can occur when identity is removed on the fly. 
                 * The 'identity' signal is triggered first, and only then 'connections'. We solve the issue by performing peers db cleanup also at 'offline' signal. */
                /*
                WISHDEBUG(LOG_CRITICAL, "clean_up_peers_db:%s%s unknown, but peer is online, this is unexpected! (luid %x %x %x... ruid: %x %x %x...)", luid_known?"":" luid", ruid_known?"":" ruid", 
                        elem->peer.luid[0], elem->peer.luid[1], elem->peer.luid[2], 
                        elem->peer.ruid[0], elem->peer.ruid[1], elem->peer.ruid[2]);
                */
            }
        }
        
    }
            
}
    
void identity_list_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = req->client->context;
    //WISHDEBUG(LOG_CRITICAL, "API ready! context is %p", ctx);
    //bson_visit(payload, elem_visitor);

    // clear out identity database
    memset(mist_api->identities, 0, sizeof(struct identity) * MIST_API_MAX_UIDS);
    
    bson_iterator it;
    bson_iterator ait;
    bson_iterator sit;
    bson_find_from_buffer(&it, payload, "data");
    bson_iterator_subiterator(&it, &ait);
    bson_find_fieldpath_value("0", &ait);
    
    while ( BSON_OBJECT == bson_iterator_type(&ait) ) {

        int free = -1;
        int i = 0;
        
        for (i=0; i<MIST_API_MAX_UIDS; i++) {
            //WISHDEBUG(LOG_CRITICAL, "   index %i", i);
            // if occupied but has no export data
            if ( mist_api->identities[i].occupied == 0 ) {
                free = i;
                break;
            }
        }
        
        if(free == -1) {
            WISHDEBUG(LOG_CRITICAL, "Memory full for identities. in mist_api\n");
            break;
        }
        
        //WISHDEBUG(LOG_CRITICAL, "  data.next is of type: %i\n", bson_iterator_type(&ait));
        bson_iterator_subiterator(&ait, &sit);
        bson_find_fieldpath_value("privkey", &sit);
        
        bool privkey = false;
        
        if (bson_iterator_type(&sit) == BSON_BOOL) {
            privkey = bson_iterator_bool(&sit);
        }
        
        bson_iterator_subiterator(&ait, &sit);
        bson_find_fieldpath_value("alias", &sit);

        if ( bson_iterator_type(&sit) == BSON_STRING ) {
            //WISHDEBUG(LOG_CRITICAL, "identity_list_cb: alias: %s\n", bson_iterator_string(&sit));
            // FIXME this string manipulation should be cleaned up
            int len = bson_iterator_string_len(&sit);
            len = len > 31 ? 32 : len;
            memcpy(mist_api->identities[free].alias, bson_iterator_string(&sit), 32);
            mist_api->identities[free].alias[31] = '\0';
            mist_api->identities[free].has_privkey = privkey;
            mist_api->identities[free].occupied = 1;
        } else {
            //WISHDEBUG(LOG_CRITICAL, "  alias is of type: %i\n", bson_iterator_type(&sit));
            continue;
        }
        
        bson_iterator_subiterator(&ait, &sit);
        bson_find_fieldpath_value("uid", &sit);

        if ( bson_iterator_type(&sit) == BSON_BINDATA && bson_iterator_bin_len(&sit) == 32 ) {
            memcpy(mist_api->identities[free].uid, bson_iterator_bin_data(&sit), 32);
        } else {
            WISHDEBUG(LOG_CRITICAL, "  uid is not 32 byte bindata\n");
            continue;
        }
        
        bson_iterator_next(&ait);
    }
    
    if (!mist_api->ready) {
        mist_api->ready = true;
        
        int buf_len = 300;
        char buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_start_array(&b, "data");
        bson_append_string(&b, "0", "ready");
        bson_append_bool(&b, "1", true);
        bson_append_finish_array(&b);
        bson_finish(&b);

        //WISHDEBUG(LOG_CRITICAL, "mist_api sending ['ready', true] signal.");

        rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));
        rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    }
    update_identity_export_db(mist_api);
    clean_up_peers_db(mist_api);
}

void wish_core_signals_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len) {
    mist_api_t* mist_api = req->client->context;
    //bson_visit("mist_api(c99) Signal from wish-core", payload);
    
    bson_iterator it;
    bson_iterator ait;
    bson_find_from_buffer(&it, payload, "data");
    bson_iterator_subiterator(&it, &ait);
    bson_find_fieldpath_value("0", &ait);
    
    if ( BSON_STRING == bson_iterator_type(&ait) ) {
        const char* signal = bson_iterator_string(&ait);
        
        if ( strncmp("identity", signal, 9) == 0 ) {
            //WISHDEBUG(LOG_CRITICAL, "identity signal from wish-core, updating identity list for mist_api");

            bson b;
            bson_init(&b);
            bson_append_string(&b, "op", "identity.list");
            bson_append_int(&b, "id", ++wish_req_id);
            bson_finish(&b);

            wish_api_request(mist_api, &b, identity_list_cb);
            bson_destroy(&b);
        }
        
        if ( strncmp("localDiscovery", signal, 15) == 0 ) {
            commission_event_wld_signal(mist_api);
        }
        if ( strncmp("friendRequesteeAccepted", signal, 24) == 0 ) {
            commission_event_friend_req_accepted_signal(mist_api);
        }
        if ( strncmp("friendRequesteeDeclined", signal, 24) == 0 ) {
            commission_event_friend_req_declined_signal(mist_api);
        }
    }
    
    bson bs;
    bson_init_with_data(&bs, payload);
    
    rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&bs), bson_size(&bs));
}

static void wish_app_ready_cb(wish_app_t* app, bool ready) {
    //WISHDEBUG(LOG_CRITICAL, "Core ready!");
    
    mist_api_t* elt = NULL;
    mist_api_t* mist_api = NULL;
    
    DL_FOREACH(mist_apis, elt) {
        if ( app == elt->wish_app ) {
            mist_api = elt;
            break;
        }
    }
    
    if (mist_api == NULL) {
        WISHDEBUG(LOG_CRITICAL, "==================================== MistApi not found!! Cannot continue! \n");
        return;
    }
    
    if (ready) {
        if(mist_api->ready) {
            return;
        }
        
        //WISHDEBUG(LOG_CRITICAL, "wish_app ready, mist_api not ready, asking for identities.");
        
        int buf_len = 300;
        char buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_string(&b, "op", "signals");
        bson_append_int(&b, "id", ++wish_req_id);
        bson_finish(&b);

        wish_api_request(mist_api, &b, wish_core_signals_cb);

        //bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_string(&b, "op", "identity.list");
        bson_append_int(&b, "id", ++wish_req_id);
        bson_finish(&b);

        wish_api_request(mist_api, &b, identity_list_cb);
    } else {
        mist_api->ready = false;
        
        //WISHDEBUG(LOG_CRITICAL, "wish_app not ready! mist_api sending ['ready', false] signal");
        
        int buf_len = 300;
        char buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_start_array(&b, "data");
        bson_append_string(&b, "0", "ready");
        bson_append_bool(&b, "1", false);
        bson_append_finish_array(&b);
        bson_finish(&b);

        rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));        
        rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));        
    }
}

static void periodic_cb(void* ctx) {
    mist_api_t* mist_api = (mist_api_t*) ctx;
    //WISHDEBUG(LOG_CRITICAL, "Periodic %p", ctx);
    
    if (mist_api->periodic != NULL) {
        mist_api->periodic(mist_api->periodic_ctx);
    }
    
    
    // wifi list cleanup 
    mist_wifi* elt;
    mist_wifi* tmp;
    
    LL_FOREACH_SAFE(mist_api->wifi_db, elt, tmp) {
        if (elt->timestamp > 0) {
            elt->timestamp--;
        } else {
            LL_DELETE(mist_api->wifi_db, elt);
            WISHDEBUG(LOG_CRITICAL, "deleting wifi: %s", elt->ssid);
            if (elt->ssid != NULL) { wish_platform_free(elt->ssid); }
            wish_platform_free(elt);
        }
    }

    commission_periodic(mist_api);
}

static void mist_api_init_rpc(mist_api_t* mist_api) {
    // FIXME this is a dirty workaround for the handlers containing the list pointers
    if (mist_api->server->handlers != NULL || methods_handler.next != NULL) {
        if ( mist_api->server->handlers == NULL ) { mist_api->server->handlers = &methods_handler; }
        return;
    }
    
    rpc_server_register(mist_api->server, &methods_handler);
    rpc_server_register(mist_api->server, &version_handler);
    
    rpc_server_register(mist_api->server, &mist_list_services_handler);
    rpc_server_register(mist_api->server, &mist_commission_add_handler);
    rpc_server_register(mist_api->server, &mist_commission_get_state_handler);
    rpc_server_register(mist_api->server, &mist_commission_list_handler);
    rpc_server_register(mist_api->server, &mist_commission_perform_handler);
    rpc_server_register(mist_api->server, &mist_commission_select_wifi_handler);
    
    rpc_server_register(mist_api->server, &mist_signals_handler);
    rpc_server_register(mist_api->server, &mist_ready_handler);
    //rpc_server_register(mist_api->server, &mist_load_app_handler);
    rpc_server_register(mist_api->server, &mist_get_service_id_handler);
    
    rpc_server_register(mist_api->server, &control_read_handler);
    rpc_server_register(mist_api->server, &control_write_handler);
    rpc_server_register(mist_api->server, &control_invoke_handler);
    rpc_server_register(mist_api->server, &control_follow_handler);
    rpc_server_register(mist_api->server, &control_model_handler);
    rpc_server_register(mist_api->server, &control_map_handler);
    rpc_server_register(mist_api->server, &control_un_map_handler);
    rpc_server_register(mist_api->server, &control_notify_handler);
    rpc_server_register(mist_api->server, &control_request_mapping_handler);
    rpc_server_register(mist_api->server, &control_signals_handler);
    
    rpc_server_register(mist_api->server, &manage_claim_handler);
    rpc_server_register(mist_api->server, &manage_peers_handler);
    rpc_server_register(mist_api->server, &manage_acl_model_handler);
    rpc_server_register(mist_api->server, &manage_acl_allow_handler);
    rpc_server_register(mist_api->server, &manage_acl_remove_allow_handler);
    rpc_server_register(mist_api->server, &manage_acl_add_user_roles_handler);
    rpc_server_register(mist_api->server, &manage_acl_remove_user_roles_handler);
    rpc_server_register(mist_api->server, &manage_acl_user_roles_handler);
    rpc_server_register(mist_api->server, &manage_user_ensure_handler);

    rpc_server_register(mist_api->server, &mist_sandbox_list_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_remove_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_list_peers_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_add_peer_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_remove_peer_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_allow_request_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_deny_request_handler);
    rpc_server_register(mist_api->server, &mist_sandbox_emit_handler);
    
    rpc_server_register(mist_api->server, &mist_wish_identity_list_handler);
    rpc_server_register(mist_api->server, &mist_wish_identity_get_handler);
    rpc_server_register(mist_api->server, &mist_wish_identity_friend_request_handler);
    rpc_server_register(mist_api->server, &mist_wish_connections_list_handler);
    rpc_server_register(mist_api->server, &mist_wish_connections_request_handler);
    rpc_server_register(mist_api->server, &mist_wish_relay_list_handler);
    rpc_server_register(mist_api->server, &mist_wish_relay_add_handler);
    rpc_server_register(mist_api->server, &mist_wish_relay_remove_handler);
    
    rpc_server_register(mist_api->server, &sandbox_login_handler);
    rpc_server_register(mist_api->server, &sandbox_logout_handler);
    rpc_server_register(mist_api->server, &sandbox_settings_handler);
    rpc_server_register(mist_api->server, &sandbox_list_peers_handler);
    rpc_server_register(mist_api->server, &sandbox_commission_list_handler);
    rpc_server_register(mist_api->server, &sandbox_commission_perform_handler);
    rpc_server_register(mist_api->server, &sandbox_commission_select_wifi_handler);
    rpc_server_register(mist_api->server, &sandbox_signals_handler);
    rpc_server_register(mist_api->server, &sandbox_methods_handler);
    rpc_server_register(mist_api->server, &sandbox_control_model_handler);
    rpc_server_register(mist_api->server, &sandbox_control_follow_handler);
    rpc_server_register(mist_api->server, &sandbox_control_read_handler);
    rpc_server_register(mist_api->server, &sandbox_control_write_handler);
    rpc_server_register(mist_api->server, &sandbox_control_invoke_handler);
    rpc_server_register(mist_api->server, &sandbox_wish_signals_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_get_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_list_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_update_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_permissions_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_export_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_sign_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_verify_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_friend_request_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_friend_request_list_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_friend_request_accept_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_friend_request_decline_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_create_handler);
    rpc_server_register(mist_api->server, &sandbox_identity_remove_handler);


}

static void send(void* ctx, uint8_t* buf, int len) {
    wish_app_t* app = ctx;
    wish_app_send_app_to_core(app, buf, len);
}

static void send_north(rpc_server_req* req, const bson* payload) {
    if (req == NULL) { WISHDEBUG(LOG_CRITICAL, "Error: send_north got NULL req."); return; }
    
    rpc_client_callback cb = req->ctx;
    
    if (cb == NULL) { WISHDEBUG(LOG_CRITICAL, "Error: send_north got NULL req->ctx used as callback."); return; }
    
    cb(NULL, req->context, bson_data(payload), bson_size(payload));
}

mist_api_t* mist_api_init(mist_app_t* mist_app) {
    mist_api_t* mist_api = wish_platform_malloc(sizeof(mist_api_t));
    memset(mist_api, 0, sizeof(mist_api_t));
    
    DL_APPEND(mist_apis, mist_api);

    sandbox_load(mist_api);
    
    /* To access mist_api inside requests to this server (via req->server->context) */
    mist_api->server = rpc_server_init(mist_api, send_north);
    strncpy(mist_api->server->name, "mist-api", MAX_RPC_SERVER_NAME_LEN);
    
    mist_api->mist_app = mist_app;
    mist_api->wish_app = mist_app->app;
    mist_api_init_rpc(mist_api);
    
    mist_api->client.name = "mist-api-client";
    mist_api->client.context = mist_api;
    mist_api->client.send = send;
    mist_api->client.send_ctx = mist_api->wish_app;
    
    mist_api->mist_app->online = online;
    mist_api->mist_app->offline = offline;
    
    mist_api->wish_app->rpc_client.context = mist_api;
    mist_api->wish_app->rpc_client.name = "mist-api-wish-app-client";
    mist_api->wish_app->ready = wish_app_ready_cb;
    mist_api->wish_app->periodic = periodic_cb;
    mist_api->wish_app->periodic_ctx = mist_api;
    
    mist_api->identities = wish_platform_malloc(sizeof(struct identity) * MIST_API_MAX_UIDS);
    memset(mist_api->identities, 0, sizeof(struct identity) * MIST_API_MAX_UIDS);
    
    /* Load peers list now */
    mist_api_peers_db_load(mist_api);
    
    return mist_api;
}

int wish_api_request_context(mist_api_t* mist_api, bson* req, rpc_client_callback cb, void* ctx) {
    rpc_client_req* client_req = rpc_client_passthru(&mist_api->wish_app->rpc_client, req, cb, ctx);
    return client_req->id;
}

int wish_api_request(mist_api_t* mist_api, bson* req, rpc_client_callback cb) {
    return wish_api_request_context(mist_api, req, cb, NULL);
}

void wish_api_request_cancel(mist_api_t* mist_api, int id) {
    rpc_client_end_by_id(&mist_api->wish_app->rpc_client, id);
}

int mist_api_request_context(mist_api_t* api, bson* req, rpc_client_callback cb, void* cb_ctx) {
    rpc_server_receive(api->server, cb, cb_ctx, req);
    return 0;
}

int mist_api_request(mist_api_t* api, bson* req, rpc_client_callback cb) {
    return mist_api_request_context(api, req, cb, NULL);
}

void mist_api_request_cancel(mist_api_t* mist_api, int id) {
    //WISHDEBUG(LOG_CRITICAL, "mist_api_request_cancel id: %i", id);
    rpc_server_end(mist_api->server, id);
}

/**

Injects sandbox_id as first argument
 
  Incoming request:
 
    { op: 'sanboxed.*', args: [arg1, args2, ...], id: n }
  
  Rewritten request should look like this:
  
    { op: 'sanboxed.*', args: [sandbox_id, arg1, args2, ...], id: n }

*/

int sandboxed_api_request_context(mist_api_t* mist_api, const char* sandbox_id, bson* req, rpc_client_callback cb, void* ctx) {
    //WISHDEBUG(LOG_CRITICAL, "sandboxed_api_request");
    
    bson_iterator it;
    bson_find(&it, req, "op");
    char* op = (char*)bson_iterator_string(&it);
    
    bson_find(&it, req, "id");
    int id = bson_iterator_int(&it);

    // find the sandbox instance
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
    
    // if the sandbox does not exist and this is not a request to login; return error
    if (sandbox == NULL) {
        if ( op == NULL || strncmp(op, "sandboxed.login", 16) != 0) {
            WISHDEBUG(LOG_CRITICAL, "sandboxed_api_request: could not find sandbox instance, and this is not a sandboxed.login request, bailing out.");
            
            rpc_server_req err_req;
            memset(&err_req, 0, sizeof(rpc_server_req));
            err_req.server = mist_api->server;
            //err_req.send = send_north;
            err_req.send_context = &err_req;
            err_req.id = id;
            err_req.ctx = cb;
            err_req.context = ctx;

            rpc_server_error_msg(&err_req, 164, "Sandbox not found, and not a login request.");
            return 0;
        }

        // allow "sandboxed.login" to pass
    }

    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    // skip the prefix "sandboxed." from op string when forwarding request
    if (memcmp(op, "sandboxed.", 10) == 0) {
        bson_append_string(&b, "op", op);
    } else {
        return 0;
    }
    
    bson_append_start_array(&b, "args");
    bson_append_binary(&b, "0", sandbox_id, SANDBOX_ID_LEN);

    bson_iterator ait;
    bson_iterator sit;
    bson_find(&ait, req, "args");

    if ( BSON_ARRAY != bson_find(&ait, req, "args") ) {
        bson_visit("sandbox_api_request args not array", (const uint8_t*) bson_data(req));
        return 0;
    }
    
    int i;
    int args_len = 0;
    
    for(i=0; i<9; i++) {
        char src[21];
        char dst[21];
    
        BSON_NUMSTR(src, i);
        BSON_NUMSTR(dst, i+1);
        
        // init the sub iterator from args array iterator
        bson_iterator_subiterator(&ait, &sit);
        
        // read the argument
        //bson_find(&it, req, src);
        bson_type type = bson_find_fieldpath_value(src, &sit);

        if (type == BSON_EOO) {
            break;
        } else {
            bson_append_element(&b, dst, &sit);
        }
        
        args_len++;
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", id);
    bson_finish(&b);

    //WISHDEBUG(LOG_CRITICAL, "sandbox_api-request re-written (sandbox %p, ctx: %p)", sandbox, ctx);
    //bson_visit("sandbox_api-request re-written:", (uint8_t*)bson_data(&b));    
    
    // FIXME check sandbox validity
    return mist_api_request_context(mist_api, &b, cb, ctx);
}

void sandboxed_api_request_cancel(mist_api_t* mist_api, const char* sandbox_id, int id) {
    // FIXME check sandbox validity
    mist_api_request_cancel(mist_api, id);
}
