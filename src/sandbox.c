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
#include "sandbox.h"
#include "utlist.h"
#include "wish_debug.h"
#include "string.h"
#include "stdbool.h"
#include "wish_protocol.h"


sandbox_t* sandbox_init() {
    sandbox_t* sandbox = wish_platform_malloc(sizeof(sandbox_t));
    memset(sandbox, 0, sizeof(sandbox_t));
    
    return sandbox;
}


bool sandbox_add_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "Sandbox add peer.");
    sandbox_peers_t* elt;
    
    sandbox_peers_t* inst = wish_platform_malloc(sizeof(sandbox_peers_t));
    
    memset(inst, 0, sizeof(sandbox_peers_t));
    
    memcpy(&inst->peer, peer, sizeof(sandbox_peers_t));

    //WISHDEBUG(LOG_CRITICAL, "  about to add peer.");

    LL_FOREACH(sandbox->peers, elt) {
        if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
             memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
             memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
             memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
             strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 ) 
        {
            //WISHDEBUG(LOG_CRITICAL, "Peer already in sandbox, bailing!");
            return false;
        }
    }
    
    /*
    if (inst->peer.online) {
        WISHDEBUG(LOG_CRITICAL, "Sandbox add peer which is ONLINE.");
    } else {
        WISHDEBUG(LOG_CRITICAL, "Sandbox add peer which is OFFLINE.");
    }
    */
    
    LL_PREPEND(sandbox->peers, inst);
    return true;
}

bool sandbox_remove_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer) {
    sandbox_peers_t* elt;
    sandbox_peers_t* tmp;
    
    if (!sandbox || !peer) {
        // sandbox or peer is null, bail
        return false;
    }
    
    LL_FOREACH_SAFE(sandbox->peers, elt, tmp) {
        if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
             memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
             memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
             memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
             strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
        {
            //WISHDEBUG(LOG_CRITICAL, "Found peer to be deleted.");
            
            LL_DELETE(sandbox->peers,elt);
            wish_platform_free(elt);
            
            return true;
        }
    }
    
    return false;
}

bool sandbox_has_peer(sandbox_t* sandbox, wish_protocol_peer_t* peer) {
    sandbox_peers_t* elt;

    LL_FOREACH(sandbox->peers, elt) {
        if ( memcmp(elt->peer.luid, peer->luid, 32) == 0 &&
             memcmp(elt->peer.ruid, peer->ruid, 32) == 0 &&
             memcmp(elt->peer.rhid, peer->rhid, 32) == 0 &&
             memcmp(elt->peer.rsid, peer->rsid, 32) == 0 &&
             strncmp(elt->peer.protocol, peer->protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
        {
            return true;
        }
    }
    
    return false;
}

