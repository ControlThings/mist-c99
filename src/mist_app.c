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
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "bson.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "mist_follow.h"
#include "mist_app.h"
#include "mist_handler.h"
#include "mist_mapping.h"

#include "bson_visit.h"
#include "utlist.h"

mist_app_t mist_apps[NUM_MIST_APPS];

mist_app_t* mist_app_get_new_context(void) {
    mist_app_t *new_ctx = NULL;
    int i = 0;
    for (i = 0; i < NUM_MIST_APPS; i++) {
        if (mist_apps[i].occupied == false) {
            mist_apps[i].occupied = true;
            new_ctx = &(mist_apps[i]);
            break;
        }
    }
    return new_ctx;
}

static int online(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "in ucp_online %p luid: %02x %02x %02x %02x ruid:  %02x %02x %02x %02x", peer, peer->luid[0], peer->luid[1], peer->luid[2], peer->luid[3], peer->ruid[0], peer->ruid[1], peer->ruid[2], peer->ruid[3]);
    
    mist_app_t *mist_app_ctx = app_ctx;
    
    if(mist_app_ctx->online != NULL) {
        mist_app_ctx->online(app_ctx, peer);
    }

    return 0;
}

static int offline(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "in ucp_offline %p", peer);

    mist_app_t *mist_app = app_ctx;
    
    if(mist_app->offline != NULL) {
        mist_app->offline(app_ctx, peer);
    }

    /* We cannot use rpc_server_end_by_ctx here, because req->ctx points to a copy of the peer made in the control.* request handler. */
    rpc_server_req* elm;
    rpc_server_req* tmp;
  
    LL_FOREACH_SAFE(mist_app->server->requests, elm, tmp) {
        wish_protocol_peer_t* ctx_peer = (wish_protocol_peer_t*) elm->ctx;
        if (memcmp(peer->luid, ctx_peer->luid, WISH_ID_LEN) == 0 && memcmp(peer->ruid, ctx_peer->ruid, WISH_ID_LEN) == 0 &&
                memcmp(peer->rhid, ctx_peer->rhid, WISH_ID_LEN) == 0 && memcmp(peer->rsid, ctx_peer->rsid, WISH_ID_LEN) == 0) {
            //WISHDEBUG(LOG_CRITICAL, "(found request, cleaning up)");
            rpc_server_req* req = elm;

            rpc_server_delete_req(req);
        }
    }
    
    return 0;
}

/* Handle a Mist frame which has been received by the ucp protocol
 * 'on_frame' callback */
void handle_mist_message(mist_app_t* mist_app, const uint8_t* data, int data_len, wish_protocol_peer_t* peer) {
    receive_device_northbound(mist_app, data, data_len, peer);
}

static int frame(void* app_ctx, const uint8_t* data, size_t data_len, wish_protocol_peer_t* peer) {
    mist_app_t *mist_app_ctx = app_ctx;
    
    handle_mist_message(mist_app_ctx, data, data_len, peer);
    return 0;
}

// expect ctx to be app_peer_t, and send data to the peer of this app. This will
// call services.send and send in case of a remote device
static void send_to_peer(void* ctx, uint8_t* buf, int buf_len) {
    //WISHDEBUG(LOG_CRITICAL, "send_to_peer: bson size in response %i", buf_len);
    //bson_visit("send_to_peer:", buf);
    
    app_peer_t* app_peer = ctx;    
    wish_app_send(app_peer->app, app_peer->peer, buf, buf_len, NULL);
}

static void send_south(rpc_server_req* req, const bson* bs) {
    mist_app_t* mist_app = req->context;
    wish_protocol_peer_t* peer = req->ctx;
    
    // where is this peer set / allocated??
    
    receive_device_southbound(mist_app, bson_data(bs), bson_size(bs), peer, NULL);
    //wish_platform_free(peer);
}

mist_app_t* start_mist_app() {
    mist_app_t* mist_app=  mist_app_get_new_context();
    
    if (mist_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not instantiate new Mist App!");
        return NULL;
    }

    memcpy(mist_app->protocol.protocol_name, "ucp", WISH_PROTOCOL_NAME_MAX_LEN);

    mist_app->protocol.on_online = online,
    mist_app->protocol.on_offline = offline,
    mist_app->protocol.on_frame = frame,
    mist_app->protocol.app_ctx = mist_app; /* Saved here so that the online, frame callbacks will receive the appropriate Mist app context */
    
    mist_app->protocol.rpc_client.name = "ucp-protocol-rpc-client";
    mist_app->protocol.rpc_client.send = send_to_peer;

    mist_app->server = rpc_server_init(mist_app, send_south);
    rpc_server_set_name(mist_app->server, "app/mist");
    
    mist_device_setup_rpc_handlers(mist_app->server);

    /* FIXME the name separately as above is redundant id app pointer is saved */
    mist_app->model.mist_app = mist_app;
    
    return mist_app;
}

/* This function is called by the device's RPC server when it needs to send a reply to an RPC request */
rpc_id receive_device_southbound(mist_app_t *mist_app, const uint8_t *reply_doc, size_t reply_doc_actual_len, wish_protocol_peer_t* peer, rpc_client_callback cb) {
    //WISHDEBUG(LOG_CRITICAL, "receive_device_southbound");
    
    /** The RPC id of the message which is sent down */
    rpc_id id = -1;
    if (reply_doc_actual_len > 0) {
        bson bs;
        bson_init_with_data(&bs, reply_doc);
        
        if (reply_doc_actual_len != bson_size(&bs)) {
            WISHDEBUG(LOG_CRITICAL, "Wish app send fail, doc len mismatch");
            return -1;
        }

        id = wish_app_send(mist_app->app, peer, bson_data(&bs), bson_size(&bs), cb);
        if (id < 0) {
            WISHDEBUG(LOG_CRITICAL, "Wish app send fail");
        }
    }
    WISHDEBUG(LOG_DEBUG, "exiting receive_device_southbound");
    return id;
}

static void mist_app_request_cb(struct wish_rpc_entry* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "mist_app_request_cb");
}

rpc_client_req* mist_app_request(mist_app_t *mist_app, wish_protocol_peer_t* peer, bson* req, rpc_client_callback cb) {
    rpc_client* client = &mist_app->protocol.rpc_client;
    
    if (cb == NULL) { WISHDEBUG(LOG_CRITICAL, "mist_app_request cb is null"); cb = mist_app_request_cb; }
    
    rpc_client_req* creq = rpc_client_request(client, req, cb, NULL);
    
    wish_app_send(mist_app->app, peer, bson_data(req), bson_size(req), NULL);
    
    return creq;
}

void mist_app_cancel(mist_app_t *mist_app, rpc_client_req *req) {
    rpc_client_end_by_id(&mist_app->protocol.rpc_client, req->id);
}

void mist_read_response(mist_app_t* mist_app, const char* epid, int id, bson* data) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);

    mist_ep* ep = NULL;
    
    enum mist_error err = mist_find_endpoint_by_name(&mist_app->model, epid, &ep);

    if (MIST_NO_ERROR != err) {
        WISHDEBUG(LOG_CRITICAL, "Mist epid not found in model. Bailing. %s", epid);
        if (req) { rpc_server_error_msg(req, 105, "Endpoint not found."); }
        return;
    }
    
    if (req == NULL) {
        bson_iterator it;
        
        if (BSON_EOO == bson_find(&it, data, "data")) {
            WISHDEBUG(LOG_CRITICAL, "No data field found. Bailing.");
            bson_visit("No data field (A):", bson_data(data));
            return;
        }
        
        bson bs;
        bson_init(&bs);
        bson_append_start_object(&bs, "data");
        bson_append_string(&bs, "id", epid);
        bson_append_element(&bs, "data", &it);
        bson_append_finish_object(&bs);
        bson_finish(&bs);
        
        rpc_server_emit_broadcast(mist_app->server, "control.follow", bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);
        
        // Send notifications to mappings
        mist_mapping_notify(mist_app, ep, data);
        
        return;
    }
    
    if ( strncmp(req->op, "control.follow", MAX_RPC_OP_LEN) == 0 ) {
        // read for a control.follow, just emit changed value
        // { id: epid, data: any }
        
        bson_iterator it;
        
        if (BSON_EOO == bson_find(&it, data, "data")) {
            WISHDEBUG(LOG_CRITICAL, "No data field found. Bailing.");
            bson_visit("No data field (B):", bson_data(data));
            return;
        }
        
        bson bs;
        bson_init(&bs);
        bson_append_start_object(&bs, "data");
        bson_append_string(&bs, "id", epid);
        bson_append_element(&bs, "data", &it);
        bson_append_finish_object(&bs);
        bson_finish(&bs);
        
        rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);
        
        return;
    }

    // From here we assume that it is a regular control.read request
    
    // copy the data property from input bson
    bson_iterator it;
    bson_find(&it, data, "data");
    
    if ( BSON_EOO == bson_iterator_type(&it) ) {
        rpc_server_error_msg(req, 7, "Read error.");
        return;
    }

    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_element(&b, "data", &it);
    bson_finish(&b);
    
    rpc_server_send(req, bson_data(&b), bson_size(&b));
}

void mist_read_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);

    if (req == NULL) { return; }
    
    if ( strncmp(req->op, "control.follow", MAX_RPC_OP_LEN) == 0 ) {
        // read error for a control.follow, just emit the error as
        // { id: epid, err: { code: int, msg: string } }
        
        int buf_len = MIST_RPC_REPLY_BUF_LEN;
        uint8_t buf[buf_len];

        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_start_object(&b, "data");
        bson_append_string(&b, "id", epid);
        bson_append_start_object(&b, "err");
        bson_append_int(&b, "code", code);
        bson_append_string(&b, "msg", msg);
        bson_append_finish_object(&b);
        bson_append_finish_object(&b);
        bson_finish(&b);
        rpc_server_emit(req, bson_data(&b), bson_size(&b));
        bson_destroy(&b);
        return;
    }

    rpc_server_error_msg(req, code, msg);
}

void mist_write_response(mist_app_t* mist_app, const char* epid, int id) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);
    
    if (req == NULL) { return; }
    
    rpc_server_send(req, NULL, 0);
}

void mist_write_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);
    
    if (req == NULL) { return; }
    
    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_start_object(&b, "data");
    bson_append_int(&b, "code", code);
    bson_append_string(&b, "msg", msg);
    bson_append_finish_object(&b);
    bson_finish(&b);
    
    rpc_server_error(req, bson_data(&b), bson_size(&b));
}

void mist_invoke_response(mist_app_t* mist_app, const char* epid, int id, bson* data) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);
    
    if (req == NULL) { return; }
    
    // copy the data property from input bson
    
    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];

    if (bson_size(data) + 32 > MIST_RPC_REPLY_BUF_LEN) {
        rpc_server_error_msg(req, 521, "Too big reply message, bailing out.");
        return;
    }
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);

    bson_iterator it;
    bson_find(&it, data, "data");
    
    if (bson_iterator_type(&it) == BSON_EOO) {
        // Invoke with no arguments
    } else {
        bson_append_element(&b, "data", &it);
    }
    
    bson_finish(&b);
    
    rpc_server_send(req, bson_data(&b), bson_size(&b));
}


void mist_invoke_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg) {
    rpc_server_req* req = rpc_server_req_by_sid(mist_app->server, id);
    
    if (req == NULL) { return; }
    
    int buf_len = MIST_RPC_REPLY_BUF_LEN;
    uint8_t buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_start_object(&b, "data");
    bson_append_int(&b, "code", code);
    bson_append_string(&b, "msg", msg);
    bson_append_finish_object(&b);
    bson_finish(&b);
    
    rpc_server_error(req, bson_data(&b), bson_size(&b));
}

void 
#ifdef COMPILING_FOR_ESP8266
__attribute__((section(".text"))) 
#endif
mist_value_changed(mist_app_t* mist_app, const char* epid) {
    mist_model* model = &mist_app->model;
    mist_ep* ep;
    
    //WISHDEBUG(LOG_CRITICAL, "mist_value_changed: %s", epid);
    
    if (mist_find_endpoint_by_name(model, epid, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "mist_value_changed but endpoint not found: %s", epid);
        return;
    }
    
    ep->dirty = true;
    
    mist_internal_read(mist_app, ep, NULL);
}

void mist_internal_read(mist_app_t* mist_app, mist_ep* ep, rpc_server_req* req) {
    ep->read(ep, NULL, req != NULL ? req->sid : 0);
}

mist_app_t* mist_app_lookup_by_wsid(uint8_t *wsid) {
    mist_app_t *app_ctx = NULL;
    int i = 0;
    for (i = 0; i < NUM_MIST_APPS; i++) {
        if (mist_apps[i].occupied == false) {
            continue;
        }
        if (memcmp(mist_apps[i].app->wsid, wsid, WISH_WSID_LEN) == 0) {
            app_ctx = &(mist_apps[i]);
            break;
        }
    }

    return app_ctx;
}
