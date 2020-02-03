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

void handle_control_model(rpc_server_req *req, const uint8_t* args);

void handle_control_write(rpc_server_req *req, const uint8_t* args);

void handle_control_follow(rpc_server_req *req, const uint8_t* args);

void handle_control_read(rpc_server_req *req, const uint8_t* args);

void handle_control_invoke(rpc_server_req *req, const uint8_t* args);

void handle_control_map(rpc_server_req *req, const uint8_t* args);

void handle_control_map_response(rpc_client_req* req, void* context, const uint8_t* payload, size_t payload_len);

void handle_control_request_mapping(rpc_server_req *req, const uint8_t* args);

void handle_control_notify(rpc_server_req *req, const uint8_t* args);

void handle_control_unmap(rpc_server_req *req, const uint8_t* args);

void handle_control_signals(rpc_server_req *req, const uint8_t* args);

#ifdef __cplusplus
}
#endif
