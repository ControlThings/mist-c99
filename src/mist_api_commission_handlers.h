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
/*! \addtogroup Commissioning
 *
 * \ingroup MistApi
 * @{
 * \details These are the RPC handler functions for Commissioning when invoked through MistApi
 *
 */

/*! \file
 * \details This is the header file for commissioning-related RPC handler functions
 */

#pragma once

void commission_wld_list_cb(rpc_client_req* creq, void* ctx, const uint8_t* payload, size_t payload_len);

void commission_set_filter(rpc_server_req *req, char *filter);

void mist_commission_list(rpc_server_req *req, const uint8_t* args);

void mist_commission_perform(rpc_server_req *req, const uint8_t* args);

void mist_commission_select_wifi(rpc_server_req *req, const uint8_t* args);