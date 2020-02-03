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

#include "wish_app.h"

#define SANDBOX_NAME_LEN    32
#define SANDBOX_ID_LEN      32

#ifdef __cplusplus
extern "C" {
#endif

    #include "stdbool.h"

    
    typedef struct sandbox_peers_s sandbox_peers_t;
    typedef struct sandbox_s sandbox_t;
        
    struct sandbox_peers_s {
        wish_protocol_peer_t peer;
        sandbox_peers_t* next;
    };

    struct sandbox_s {
        uint8_t name[SANDBOX_NAME_LEN];
        uint8_t sandbox_id[SANDBOX_ID_LEN];
        bool online;
        sandbox_peers_t* peers;
        sandbox_t* next;
    };

    sandbox_t* sandbox_init();

    bool sandbox_add_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer);
    
    bool sandbox_remove_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer);
    
    bool sandbox_has_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer);
    
#ifdef __cplusplus
}
#endif

