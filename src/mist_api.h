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

#include "wish_app.h"
#include "mist_app.h"
#include "wish_rpc.h"
#include "bson.h"
#include "sandbox.h"
#include "mist_api_commission.h"

#ifndef MIST_API_MAX_UIDS
#define MIST_API_MAX_UIDS (128)
#endif //MIST_API_MAX_UIDS

#ifndef MIST_API_REQUEST_POOL_SIZE
#define MIST_API_REQUEST_POOL_SIZE 0
#endif //MIST_API_REQUEST_POOL_SIZE
    
    struct mist_api_context;
    
    typedef void (*mist_api_periodic_cb)(void* ctx);

    struct identity {
        // FIXME use real lengths
        char alias[32];
        bool has_privkey;
        uint8_t uid[32];
        uint8_t occupied;
        uint8_t export_occupied;
        uint8_t export_data[512];
        int export_len;
    };
    
    typedef struct mist_wifi_s mist_wifi;
    
    typedef struct mist_wifi_s {
        char* ssid;
        int level;
        uint32_t capabilities;
        int timestamp;
        mist_wifi* next;
    } mist_wifi;
    
    typedef struct peers_list_s peers_list;
    
    typedef struct peers_list_s {
        wish_protocol_peer_t peer;
        peers_list* next;
    } peers_list;  

    typedef struct mist_api_context {
        wish_app_t* wish_app;
        mist_app_t* mist_app;
        
        bool ready;
        
        struct identity* identities;
        
        mist_api_periodic_cb periodic;
        void* periodic_ctx;
        
        peers_list* peers_db;
        
        // sandbox for 3-rd party access to api
        sandbox_t* sandbox_db;
        mist_wifi* wifi_db;

        rpc_client client;
        rpc_server* server;
        rpc_server_req request_pool[MIST_API_REQUEST_POOL_SIZE];
        
        commissioning commissioning;
        
        struct mist_api_context* next;
        struct mist_api_context* prev;
    } mist_api_t;
    
    mist_api_t* mist_api_init(mist_app_t* mist_app);
    
    int wish_api_request_context(mist_api_t* mist_api, bson* bs, rpc_client_callback cb, void* ctx);

    int wish_api_request(mist_api_t* mist_api, bson* bs, rpc_client_callback cb);

    void wish_api_request_cancel(mist_api_t* mist_api, int id);

    int mist_api_request_context(mist_api_t* mist_api, bson* bs, rpc_client_callback cb, void* cb_ctx);
    
    int mist_api_request(mist_api_t* mist_api, bson* bs, rpc_client_callback cb);
    
    void mist_api_request_cancel(mist_api_t* mist_api, int id);
    
    wish_protocol_peer_t* mist_api_peer_find(mist_api_t* mist_api, wish_protocol_peer_t* peer);
    
    int sandboxed_api_request_context(mist_api_t* mist_api, const char* sandbox_id, bson* req, rpc_client_callback cb, void* cb_ctx);

    void sandboxed_api_request_cancel(mist_api_t* mist_api, const char* sandbox_id, int id);

#ifdef __cplusplus
}
#endif


