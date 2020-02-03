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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wish_app.h"
#include "uv.h"
#include "wish_core_client.h"

#include "mist_api.h"

#include "mist_model.h"
#include "mist_handler.h"


#include "bson_visit.h"

#define MIST_APP_NAME_DEFAULT "Mist example app"
static char app_name[WISH_APP_NAME_MAX_LEN];

static enum mist_error endpoint_read(mist_ep* ep, wish_protocol_peer_t* peer, int request_id);
static enum mist_error endpoint_write(mist_ep* ep, wish_protocol_peer_t* peer, int request_id, bson* args);

static mist_ep mist_super_ep = {.id = "mist", .label = "", .type = MIST_TYPE_STRING, .read = endpoint_read};
static mist_ep mist_name_ep = {.id = "name", .label = "Name", .type = MIST_TYPE_STRING, .read = endpoint_read};
static mist_ep example_ep = {.id = "exampleEndpoint", .label = "Example endpoint", .type = MIST_TYPE_STRING, .read = endpoint_read, .write = endpoint_write };

char *example_string = NULL;

wish_app_t *app = NULL;
mist_app_t *mist_app = NULL;


static enum mist_error endpoint_read(mist_ep* ep, wish_protocol_peer_t* peer, int request_id) {
    WISHDEBUG(LOG_CRITICAL, "in endpoint_read");

    char full_epid[MIST_EPID_LEN];
    mist_ep_full_epid(ep, full_epid);
    
    size_t result_max_len = 100;
    uint8_t result[result_max_len];
    bson bs;
    bson_init_buffer(&bs, (char*) result, result_max_len);
    
    if (ep == &mist_super_ep) {
        bson_append_string(&bs, "data", "");
    }
    else if (ep == &mist_name_ep) {
        bson_append_string(&bs, "data", app_name);
    }
    else if (ep == &example_ep) {
        if (example_string) {
            bson_append_string(&bs, "data", example_string);
        }
        else {
            bson_append_string(&bs, "data", "Example string has not yet written!");
        }
    }

    bson_finish(&bs);
    mist_read_response(ep->model->mist_app, full_epid, request_id, &bs);
    
    WISHDEBUG(LOG_CRITICAL, "exit endpoint_read");
    return MIST_NO_ERROR;
}

static enum mist_error endpoint_write(mist_ep* ep, wish_protocol_peer_t* peer, int request_id, bson* args) {
    WISHDEBUG(LOG_CRITICAL, "in endpoint_write");

    /** Full epid will be used for mist_write_response(), but also the filename for geo and sitename data! */
    char full_epid[MIST_EPID_LEN]; 
    mist_ep_full_epid(ep, full_epid);

    bson_iterator new_value_it;
    if ( BSON_EOO == bson_find(&new_value_it, args, "args") ) { 
        mist_write_error(ep->model->mist_app, ep->id, request_id, 7, "Bad BSON structure, no element 'args'");
        fprintf(stderr, "mist_name_write: no element data");
        return MIST_ERROR; 
    }

    const char *str = bson_iterator_string(&new_value_it);
    size_t str_len = bson_iterator_string_len(&new_value_it);

    printf("Wrote: %s", str);
    if (example_string != NULL) {
        free(example_string);
    }
    example_string = strndup(str, str_len);
    
    mist_write_response(ep->model->mist_app, full_epid, request_id);
    return MIST_NO_ERROR;
}

static void core_list_identities_cb(struct wish_rpc_entry* req, void* ctx, const uint8_t* data, size_t data_len) {
    bson_visit("core_list_identities_cb", data);
}

static void make_some_calls(mist_app_t *mist_app) {
    bson bs;
    
    bson_init(&bs);
    bson_append_string(&bs, "op", "identity.list");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", 0);
    bson_finish(&bs);
    
    wish_app_request(mist_app->app, &bs, core_list_identities_cb, NULL);
    bson_destroy(&bs);
    
}

static void init(wish_app_t* app, bool ready) {
    if (ready) {
        WISHDEBUG(LOG_CRITICAL, "API ready!");
        make_some_calls(mist_app);
    } else {
        WISHDEBUG(LOG_CRITICAL, "API not ready!");
    }
}

int main(int argc, char** argv) {

    wish_platform_set_malloc(malloc);
    wish_platform_set_realloc(realloc);
    wish_platform_set_free(free);
    srandom(time(NULL));
    wish_platform_set_rng(random);
    wish_platform_set_vprintf(vprintf);
    wish_platform_set_vsprintf(vsprintf);  

    /* TODO: need also init wish_fs layer in similar fashion */

    mist_app = start_mist_app();

    if (mist_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return 1;
    }

    char *test_instance_name = getenv("TEST_INSTANCE_NAME");

    if (test_instance_name) {
        strncpy(app_name, test_instance_name, WISH_APP_NAME_MAX_LEN-1);
    }
    else {
        strncpy(app_name, MIST_APP_NAME_DEFAULT, WISH_APP_NAME_MAX_LEN-1 );
    }

    printf("App name: %s\n", app_name);

    app = wish_app_create(app_name);

    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Failed creating wish app");
        return 1; 
    }

    wish_app_add_protocol(app, &(mist_app->protocol));
    mist_app->app = app;

    mist_ep_add(&(mist_app->model), NULL, &mist_super_ep);
    /* FIXME should use parent's full path, just to illustrate */
    mist_ep_add(&(mist_app->model), mist_super_ep.id, &mist_name_ep);
    mist_ep_add(&(mist_app->model), NULL, &example_ep);

    app->ready = init;
    
    if (app == NULL) {
        printf("Failed creating wish app");
        return 1;
    }
    
    wish_core_client_init(app);
    
    return 0;
}
