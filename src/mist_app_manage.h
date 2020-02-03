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

#include "wish_rpc.h"
#include "stdint.h"
#include "stddef.h"

    
/**
 * @deprecated{manage.claim is deprecated, instead the MistConfig app has a special invocable endpoint that is used for claiming a device}
 */
void handle_manage_claim(rpc_server_req *req, const uint8_t* args);

void handle_manage_user_ensure_cb(rpc_client_req* req, void* ctx, const uint8_t* payload, size_t payload_len);

void handle_manage_user_ensure(rpc_server_req *req, const uint8_t* args);


#ifdef __cplusplus
}
#endif
