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

#include "mist_api.h"
    
void mist_port_wifi_join(mist_api_t* mist_api, const char* ssid, const char* password);

void mist_port_wifi_join_cb(mist_api_t* mist_api, wifi_join result);

void mist_port_wifi_list_cb(mist_api_t* mist_api, bson* wifi_list);

void mist_port_wifi_list(mist_api_t* mist_api);

#ifdef __cplusplus
}
#endif

