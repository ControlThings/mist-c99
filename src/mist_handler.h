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

#include <stdint.h>
#include "mist_app.h"
    
/**
 * Function for feeding Mist message to the Device API RPC server 
 * 
 * @param mist_app
 * @param data
 * @param data_len
 * @param peer
 */
void receive_device_northbound(mist_app_t* mist_app, const uint8_t* data, int data_len, wish_protocol_peer_t* peer);

void mist_device_setup_rpc_handlers(rpc_server* server);

#ifdef __cplusplus
}
#endif
