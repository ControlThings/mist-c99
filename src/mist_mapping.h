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
/* 
 * File:   mist_mapping.h
 * Author: jan
 *
 * Created on December 1, 2016, 2:20 PM
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_protocol.h"
#include "mist_model.h"
#include "wish_app.h"
    
#define MAPPINGS_MAX 2
    
#define MAPPING_ID_LEN 10

typedef struct {
    bool occupied;
    /* The peer which made this mapping */
    wish_protocol_peer_t peer;
    char mapping_id[MAPPING_ID_LEN];
    /* The endpoint id which is the target of this mapping (from the point of view of control.map) */
    char dst_endpoint_id[MIST_EPID_LEN];
    /* The endpoint id which is the src of this mapping (from the point of view of control.map) */
    char src_endpoint_id[MIST_EPID_LEN];
    /* The service id of the device that has is the target of this mapping. Note: this will be removed when mappings are moved to be part of app struct */
    uint8_t wsid[WISH_WSID_LEN];
} mist_mapping_t;

bool mist_mapping_save(mist_app_t* mist_app, wish_protocol_peer_t* peer, char* unique_id, char* src_epid, char* dst_epid);

void mist_mapping_notify(mist_app_t* mist_app, mist_ep* ep, bson* bs);

int mist_mapping_get_new_id(mist_app_t* mist_app);

bool mist_mapping_delete(mist_app_t* mist_app, wish_protocol_peer_t* peer, char* mapping_id);

void mist_mapping_list(mist_app_t* mist_app, mist_ep *ep, bson *bs);


#ifdef __cplusplus
}
#endif

