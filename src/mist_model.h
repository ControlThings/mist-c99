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
#include "wish_protocol.h"
#include "bson.h"
    
/* Mist model-related functions */

enum mist_type {
    MIST_TYPE_BOOL,     /* a true/false value (BSON bool) */
    MIST_TYPE_FLOAT,    /* A floating point value (actually a BSON double) */
    MIST_TYPE_INT,       /* A 32-bit signed integer (BSON int32) */
    MIST_TYPE_STRING,   /* A string, which can be MIST_STRING_EP_MAX_LEN
    bytes long at most */
    MIST_TYPE_INVOKE,   /* An endpoint which represent a function you
    can call, "invoke" so to speak */
};

enum mist_error {
    MIST_NO_ERROR,
    MIST_ERROR,
    MIST_ASYNC, // used when control.invoke is asynchronoulsy executed
    MIST_MAX_ENDPOINTS_REACHED,
    MIST_MALLOC_FAIL,
};

typedef struct mist_buffer {
    char* base;
    int len;
} mist_buf;

struct mist_app;
struct mist_model_s;

typedef struct mist_endpoint mist_ep;

struct mist_endpoint {
    struct mist_model_s* model;
    char* id;       /* ID of the item (=the name of the document) */
    char* label;    /* Clear text label */
    enum mist_type type;
    char* unit;
    bool readable;
    bool writable;
    bool invokable;
    enum mist_error (*read)(mist_ep* ep, wish_protocol_peer_t* peer, int id);
    enum mist_error (*write)(mist_ep* ep, wish_protocol_peer_t* peer, int id, bson* args);
    enum mist_error (*invoke)(mist_ep* ep, wish_protocol_peer_t* peer, int id, bson* args);
    struct mist_endpoint * next;
    struct mist_endpoint * prev;
    struct mist_endpoint * child; // pointer to first child
    struct mist_endpoint * parent;
    bool dirty;
    /* Used in float type */
    char *scaling;
};

#define MIST_MODEL_NAME_MAX_LEN 16

#define MIST_EPID_LEN 128

typedef struct mist_model_s {
    mist_ep* endpoints;
    /* Reference to mist app FIXME need help with forward declarations! */
    struct mist_app* mist_app;
} mist_model;

enum mist_error mist_find_endpoint_by_name(mist_model* model, const char* id, mist_ep** result);

enum mist_error mist_ep_full_epid(mist_ep* ep, char id_out[MIST_EPID_LEN]);

/**
 * Add a Mist endpoint to model.
 * 
 * @note mist_model_changed() can be used to signal change in model to listeners
 */
enum mist_error mist_ep_add(mist_model* model, const char* path, mist_ep* ep);

/**
 * Remove a Mist endpoint.
 * @param model The model which to which the endpoint is to be removed
 * @param id The full epid of the endpoint
 * @param ep_destroy_fn A pointer to an application-supplied clean-up function, which will be called when the endpoint is removed from model. The purpose is to allow the resource to be free'd, if the application allocated the mist_ep structure (or parts of the structure) from the heap. NULL if no such function is to be called.
 * @return MIST_ERROR if the endpoint was not found, in this case removed_ep is not valid. MIST_NO_ERROR if the endpoint was removed and removed_ep is valid.
 * @note mist_model_changed() can be used to signal change in model to listeners
 */
enum mist_error mist_ep_remove(mist_model* model, const char* id, void (*ep_destroy_fn)(mist_ep *));

/** 
 * Generate BSON representation of internal model
 * 
 * This function will generate a complete "model" document, which is to
 * be embedded in the "data" document of the control.model reply. 
 * The document will be created in the buffer supplied as parameter
 * "model_do"c. The buffer will be initialised as a document first.
 * The caller must make sure that the array is large enough, or else the
 * operation will fail and error is returned. 
 * */
int model_generate_bson(mist_model* model, bson* bs);

/**
 * Indicate that the Model has changed. Anyone having issued the 'control.signals' request will thereby receive the 'model' signal.
 */
enum mist_error mist_model_changed(mist_model *model);

#ifdef __cplusplus
}
#endif
