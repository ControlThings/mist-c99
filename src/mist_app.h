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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "wish_protocol.h"
#include "mist_model.h"

/* This defines the size of the buffer were the RPC reply will be built */
#ifndef MIST_RPC_REPLY_BUF_LEN
#define MIST_RPC_REPLY_BUF_LEN 512*1024
#endif //MIST_RPC_REPLY_BUF_LEN

#define MIST_APP_NAME_MAX_LEN 16

/** Maximum number of Mist apps you can have. Note that this cannot be smaller than NUM_WISH_APPS */
#ifndef NUM_MIST_APPS
#define NUM_MIST_APPS 5
#endif //NUM_MIST_APPS

#if NUM_MIST_APPS > NUM_WISH_APPS
#error Max number of mist apps cannot be larger than number of wish apps
#endif

typedef struct mist_app {
    char name[MIST_APP_NAME_MAX_LEN];
    bool occupied;
    wish_app_t* app;
    wish_protocol_handler_t protocol;
    mist_model model;
    rpc_server* server;
    void (*online)(struct mist_app* app, wish_protocol_peer_t* peer);
    void (*offline)(struct mist_app* app, wish_protocol_peer_t* peer);
} mist_app_t;

mist_app_t* mist_app_get_new_context(void);

mist_app_t* start_mist_app(void);

rpc_id receive_device_southbound(mist_app_t* mist_app, const uint8_t *reply_doc, size_t reply_doc_actual_len, wish_protocol_peer_t* peer, rpc_client_callback cb);

rpc_client_req* mist_app_request(mist_app_t* mist_app, wish_protocol_peer_t* peer, bson* req, rpc_client_callback cb);

void mist_app_cancel(mist_app_t *mist_app, rpc_client_req *req);

void mist_read_response(mist_app_t* mist_app, const char* epid, int id, bson* data);

void mist_read_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg);

void mist_write_response(mist_app_t* mist_app, const char* epid, int id);

void mist_write_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg);

void mist_invoke_response(mist_app_t* mist_app, const char* epid, int id, bson* data);

void mist_invoke_error(mist_app_t* mist_app, const char* epid, int id, int code, const char* msg);

void mist_value_changed(mist_app_t* mist_app, const char* epid);

void mist_internal_read(mist_app_t* mist_app, mist_ep* ep, rpc_server_req* req);

void handle_mist_message(mist_app_t* mist_app, const uint8_t* data, int data_len, wish_protocol_peer_t* peer);

mist_app_t* mist_app_lookup_by_wsid(uint8_t *wsid);

#ifdef __cplusplus
}
#endif
