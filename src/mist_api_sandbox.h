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

#define SANDBOX_FILE   "sandbox.bin"
    
#include "mist_api.h"
#include "sandbox.h"

/* Sandbox API */
    
void mist_sandbox_list(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_remove(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_add_peer(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_remove_peer(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_allow_request(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_deny_request(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_emit(rpc_server_req* req, const uint8_t* args);

void mist_sandbox_remove_peers_by_uid(mist_api_t* mist_api, const char* uid);

/* Sandboxed API */

/**
 * Reads arguments (sandboxId: Buffer(32), coreId: null|Peer, passThroughArgs...) 
 * and passes the request along to local core if coreId is null otherwise to 
 * remote core using (luid, ruid, rhid) from Peer.
 * 
 * @param req
 * @param args
 */
void sandbox_wish_passthru(rpc_server_req* req, const uint8_t* args);

void sandbox_methods(rpc_server_req* req, const uint8_t* args);

void sandbox_signals(rpc_server_req* req, const uint8_t* args);

void sandbox_list_peers(rpc_server_req* req, const uint8_t* args);

void sandbox_commission_list(rpc_server_req* req, const uint8_t* args);

void sandbox_commission_perform(rpc_server_req* req, const uint8_t* args);

void sandbox_commission_select_wifi(rpc_server_req* req, const uint8_t* args);

void sandbox_settings(rpc_server_req* req, const uint8_t* args);

void sandbox_login(rpc_server_req* req, const uint8_t* args);

void sandbox_logout(rpc_server_req* req, const uint8_t* args);

void sandbox_wish_identity_update(rpc_server_req* req, const uint8_t* args);

void sandbox_wish_identity_permissions(rpc_server_req* req, const uint8_t* args);

void sandbox_wish_identity_sign(rpc_server_req* req, const uint8_t* args);

void sandbox_wish_identity_friend_request(rpc_server_req* req, const uint8_t* args);

/* Internals */

sandbox_t* mist_sandbox_by_id(mist_api_t* mist_api, const char* id);

void sandbox_load(mist_api_t* mist_api);

void sandbox_save(mist_api_t* mist_api);

void sandbox_passthrough_end(rpc_server_req *req);

void sandbox_passthrough(rpc_server_req* req, const uint8_t* args);

void sandbox_signals_emit(mist_api_t* mist_api, char* signal);

void sandbox_identity_remove(rpc_server_req* req, const uint8_t* args);

#ifdef __cplusplus
}
#endif
