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
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "utlist.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_debug.h"
#include "mist_api.h"
#include "mist_api_commission_handlers.h"

// FIXME request contexts are taken, so no trivial way of passing the filter 
//  from sandbox_commission_list to sandbox_wld_list_cb.
static char* commission_list_filter;

void commission_set_filter(rpc_server_req *req, char *filter) {
    if (filter != NULL) {
        commission_list_filter = strdup(filter);
    }
    else {
        commission_list_filter = NULL;
    }
}

void commission_wld_list_cb(rpc_client_req* creq, void* ctx, const uint8_t* payload, size_t payload_len) {
    rpc_server_req* req = ctx;
    
    // set in sandbox commission list, NULL or string pointer
    const char* filter = commission_list_filter;
    
    mist_api_t* mist_api = creq->client->context;
    
    if (creq->err) {
        WISHDEBUG(LOG_CRITICAL, "sandbox_wld_list_cb was an error...! %p", ctx);
        rpc_server_error(req, payload, payload_len);
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    mist_wifi* elt;
    int c = 0;
    
    LL_FOREACH(mist_api->wifi_db, elt) {
        char s[21];
        bson_numstr(s, c++);
        bson_append_start_object(&bs, s);
        bson_append_string(&bs, "type", "wifi");
        bson_append_string(&bs, "ssid", elt->ssid);
        bson_append_finish_object(&bs);
    }

    bson b;
    bson_init_with_data(&b, payload);
    
    bson_iterator it;
    bson_find_from_buffer(&it, payload, "data");
    
    bson_iterator sit;
    bson_iterator_subiterator(&it, &sit);
    
    while ( bson_iterator_next(&sit) == BSON_OBJECT ) {
        if (filter) {
            bson_iterator oit;
            if ( BSON_STRING == bson_find_from_buffer(&oit, bson_iterator_value(&sit), "class") ) {
                if ( strcmp(bson_iterator_string(&oit), filter) != 0 ) { continue; }
            } else {
                continue;
            }
        }
        
        char s[21];
        bson_numstr(s, c++);
        bson_append_element(&bs, s, &sit);
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);

    if (commission_list_filter != NULL) {
        wish_platform_free(commission_list_filter);
        commission_list_filter = NULL;
    }
}

void mist_commission_list(rpc_server_req *req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;

    if (BSON_STRING == bson_find_from_buffer(&it, args, "0") ) {
        commission_set_filter(req, (char*) bson_iterator_string(&it));
    } else {
        commission_set_filter(req, NULL);
    }
    
    bson b;
    bson_init(&b);
    bson_append_string(&b, "op", "wld.list");
    bson_append_start_array(&b, "args");
    bson_append_finish_array(&b);
    bson_append_int(&b, "id",req->id);
    bson_finish(&b);
    
    rpc_server_passthru(req, &mist_api->mist_app->app->rpc_client, &b, commission_wld_list_cb);
    bson_destroy(&b);

}

void mist_commission_perform(rpc_server_req *req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_BINDATA != bson_find_fieldpath_value("0", &it) ) {
        rpc_server_error_msg(req, 667, "Commission luid invalid.");
        return;
    }
    
    const char* luid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("1.type", &it) ) {
        rpc_server_error_msg(req, 667, "Commission type not string.");
        return;
    }
    
    const char* type = bson_iterator_string(&it);
    
    if (strncmp("wifi", type, 5) == 0) {
        bson_iterator_from_buffer(&it, args);

        if ( BSON_STRING != bson_find_fieldpath_value("1.ssid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission wifi ssid not string.");
            return;
        }

        const char* ssid = bson_iterator_string(&it);

        bson_iterator_from_buffer(&it, args);
        
        const char* password = NULL;
        
        if ( BSON_STRING == bson_find_fieldpath_value("1.password", &it) ) {
            password = bson_iterator_string(&it);
        }

        const char* class = NULL;
        
        bson_iterator_from_buffer(&it, args);
        
        if ( BSON_STRING == bson_find_fieldpath_value("1.class", &it) ) {
            class = bson_iterator_string(&it);
        }

        mist_api->commissioning.req_sid = req->sid;
        mist_api->commissioning.via_sandbox = false;
        
        // do the wifi thing, try to join the wifi given
        commission_event_start_wifi(mist_api, luid, ssid, password, class);
        
        //mist_port_wifi_join(ssid, NULL);
    } else if (strncmp("local", type, 6) == 0) {
        // do the local thing, send friend request and wait for response
        
        bson_iterator_from_buffer(&it, args);

        if ( BSON_BINDATA != bson_find_fieldpath_value("1.ruid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission ruid not buffer.");
            return;
        }

        const char* ruid = bson_iterator_bin_data(&it);
        
        bson_iterator_from_buffer(&it, args);

        if ( BSON_BINDATA != bson_find_fieldpath_value("1.rhid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission rhid not buffer.");
            return;
        }

        const char* rhid = bson_iterator_bin_data(&it);
        
        bson_iterator_from_buffer(&it, args);
        
        const char* class = NULL;
        
        if ( BSON_STRING == bson_find_fieldpath_value("1.class", &it) ) {
            class = bson_iterator_string(&it);
        }
        
        mist_api->commissioning.req_sid = req->sid;
        mist_api->commissioning.via_sandbox = false;
        
        commission_event_start_wld(mist_api, luid, ruid, rhid, class);
    } else {
        rpc_server_error_msg(req, 667, "Commission type unknown, expecting wifi or local.");
        return;
    }
    
    /*
    // emit progress
    bson bs;
    bson_init(&bs);
    bson_append_int(&bs, "data", mist_api->commissioning.state);
    bson_finish(&bs);
    
    rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    //rpc_server_emit_broadcast(req->server, "commission.perform", bson_data(), bson_size());
    
    bson_destroy(&bs);
    */
    
    //rpc_server_error_msg(req, 101, "Not implemented.");

}

void mist_commission_select_wifi(rpc_server_req *req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("0.type", &it) ) {
        rpc_server_error_msg(req, 668, "Type must be string.");
        return;
    }
    
    const char* type = bson_iterator_string(&it);
    
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("0.ssid", &it) ) {
        rpc_server_error_msg(req, 668, "SSID must be string.");
        return;
    }
    
    const char* ssid = bson_iterator_string(&it);
    
    bson_iterator_from_buffer(&it, args);
    const char* password = NULL;
    
    if ( BSON_STRING == bson_find_fieldpath_value("0.password", &it) ) {
        password = bson_iterator_string(&it);
        //rpc_server_error_msg(req, 668, "Password must be string");
        //return;
    }

    
    commission_event_select_wifi(mist_api, type, ssid, password);
    
    // respond
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    bson_destroy(&bs);
}