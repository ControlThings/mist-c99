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
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "mist_app.h"
#include "mist_model.h"
#include "mist_mapping.h"
#include "wish_platform.h"
#include "wish_debug.h"
#include "wish_utils.h"
#include "bson.h"

int model_generate_bson(mist_model* model, bson* bs) {
    mist_ep* curr_ep = model->endpoints;
    
    int depth = 0;
    
    while (curr_ep != NULL) {
        depth++;
        bson_append_start_object(bs, curr_ep->id);
        bson_append_string(bs, "label", curr_ep->label);
        char* type_str = "";
        switch (curr_ep->type) {
        case MIST_TYPE_BOOL:
            type_str = "bool";
            break;
        case MIST_TYPE_FLOAT:
            type_str = "float";
            break;
        case MIST_TYPE_INT:
            type_str = "int";
            break;
        case MIST_TYPE_STRING:
            type_str = "string";
            break;
        case MIST_TYPE_INVOKE:
            type_str = "invoke";
            break;
        }
        bson_append_string(bs, "type", type_str);
        
        if (curr_ep->unit && strnlen(curr_ep->unit, 1)>0) {
            bson_append_string(bs, "unit", curr_ep->unit); }
        if (curr_ep->readable) {
            bson_append_bool(bs, "read", curr_ep->readable); }
        if (curr_ep->writable) {
            bson_append_bool(bs, "write", curr_ep->writable); }
        if (curr_ep->invokable) {
            bson_append_bool(bs, "invoke", curr_ep->invokable); }
        if (curr_ep->scaling != NULL && strnlen(curr_ep->scaling, 1)>0) {
            bson_append_string(bs, "scale", curr_ep->scaling);
        }

        mist_mapping_list(model->mist_app, curr_ep, bs);
        
        if (curr_ep->child != NULL) {
            bson_append_start_object(bs, "#");
            depth++;
            curr_ep = curr_ep->child;
            continue;
        }
        
        if (curr_ep->next != NULL) {
            bson_append_finish_object(bs);
            depth--;
            curr_ep = curr_ep->next;
            continue;
        }
        
        if (curr_ep->parent == NULL) {
            curr_ep = NULL;
        } else {
            while (curr_ep->parent != NULL) {
                depth -= 2;
                bson_append_finish_object(bs);
                bson_append_finish_object(bs);
                curr_ep = curr_ep->parent;
                
                if (curr_ep->next != NULL) {
                    bson_append_finish_object(bs);
                    depth--;
                    curr_ep = curr_ep->next;
                    break;
                } else if (curr_ep->parent == NULL) {
                    curr_ep = NULL;
                    break;
                }
            }
        }
    }
    
    while (depth-- >= 0) {
        bson_append_finish_object(bs);
    }
    
    if (bs->err) {
        WISHDEBUG(LOG_CRITICAL, "Bson error %d in mist model", bs->err);
    }
    return 0;
}

static void emit_model_changed_signal(mist_app_t *app) {
    int buf_len = 300;
    char buf[buf_len];

    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "model");
    bson_append_finish_array(&b);
    bson_finish(&b);
    rpc_server_emit_broadcast(app->server, "control.signals", bson_data(&b), bson_size(&b));
    
}

enum mist_error mist_ep_add(mist_model* model, const char* path, mist_ep* ep) {
    enum mist_error retval = MIST_NO_ERROR;

    mist_ep* elt = NULL;
    
    if (path == NULL) {
        if (model->endpoints == NULL) {
            // add as only (first) root element
            model->endpoints = ep;
        } else {
            // add as last root element
            elt = model->endpoints;
            while (elt->next != NULL) { elt = elt->next; }
            elt->next = ep;
            ep->prev = elt;
        }
    } else {
        if (MIST_NO_ERROR != mist_find_endpoint_by_name(model, path, &elt) ) {
            return MIST_ERROR;
        }
        if (elt->child == NULL) {
            // add as only (first) child to this element
            ep->parent = elt;
            elt->child = ep;
        } else {
            // add as last child to this element
            elt = elt->child;
            while (elt->next != NULL) { elt = elt->next; }
            elt->next = ep;
            ep->prev = elt;
            ep->parent = elt->parent;
        }
    }

    ep->model = model;
    ep->readable = ep->read != NULL;
    ep->writable = ep->write != NULL;
    ep->invokable = ep->invoke != NULL;
    
    return retval;
}

static void mist_ep_remove_ep(mist_model* model, mist_ep* ep, void (*ep_destroy_fn)(mist_ep *)) {
    //WISHDEBUG(LOG_CRITICAL, "Removing %s", ep->id);
    mist_ep* elt = ep;

    while (ep->child) {
        // remove children one by one
        //WISHDEBUG(LOG_CRITICAL, "(child) %s", ep->child->id);
        elt = ep->child;
        ep->child = ep->child->next;
        mist_ep_remove_ep(model, elt, ep_destroy_fn);
    }
    
    elt = ep;

    if (elt->next == NULL && elt->prev == NULL && elt->child == NULL) {
        if (elt->parent != NULL) {
            // an only child, delete and remove parents child pointer
            elt->parent->child = NULL;
        } else {
            // an only root element
            model->endpoints = NULL;
        }
        
        if (ep_destroy_fn) {
            ep_destroy_fn(elt);
        }
        
        return;
    }
    
    if (ep->prev != NULL) {
        // set the prev to point to our next
        ep->prev->next = ep->next;
    }
    if (ep->next != NULL) {
        // set the next prev to point to our prev
        ep->next->prev = ep->prev;
    }
    if (model->endpoints == ep) {
        // removing the first element from root
        model->endpoints = ep->next;
    }
    
    if (ep_destroy_fn) {
        ep_destroy_fn(ep);
    }
}

/**
 * Remove a Mist endpoint.
 * @param model The model which to which the endpoint is to be removed
 * @param id The full epid of the endpoint
 * @param ep_destroy_fn A pointer to an application-supplied clean-up function, which will be called when the endpoint is removed from model. The purpose is to allow the resource to be free'd, if the application allocated the mist_ep structure (or parts of the structure) from the heap. NULL if no such function is to be called.
 * @return MIST_ERROR if the endpoint was not found, in this case removed_ep is not valid. MIST_NO_ERROR if the endpoint was removed and removed_ep is valid.
 */
enum mist_error mist_ep_remove(mist_model* model, const char* id, void (*ep_destroy_fn)(mist_ep *)) {
    enum mist_error retval = MIST_NO_ERROR;

    mist_ep* ep;

    if (mist_find_endpoint_by_name(model, id, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "Could not find the endpoint %s", id);
        return MIST_ERROR;
    }

    mist_ep_remove_ep(model, ep, ep_destroy_fn);
    
    return retval;
}

enum mist_error mist_find_endpoint_by_name(mist_model* model, const char* id, mist_ep** result) {
    if(id == NULL) { return MIST_ERROR; }
    
     
    
    int id_len = strlen(id);
    
    char* p = memchr(id, '.', id_len);
    int cursor = 0;
    
    mist_ep* curr_ep = model->endpoints;
    
    bool last = false;
    
    while (curr_ep != NULL) {
        if (p == NULL) { p = (char*) &id[id_len]; last = true; }
        
        int epid_len = strlen(curr_ep->id);
        
        if (strncmp(curr_ep->id, &id[cursor], epid_len ) == 0) {
            /* Note: in this case curr_ep->id can be a substring of &id[cursor], we need to be on our guard for that */
            if (last) {
                if (cursor + epid_len < id_len) {
                    /* curr_ep->id is actually a substring of &id[cursor], curr_ep is not the endpoint we are looking for. */
                    curr_ep = curr_ep->next;
                    continue;
                }

                *result = curr_ep;
                return MIST_NO_ERROR;
            } else {
                /* Now we need to check that the matched substring in full id string is actually the name of the parent endpoint */
                if (id[cursor+epid_len] != '.') {
                    /* It is not, but is rather a true substring, like in the case: we are looking for "item16.subitem", and we are now looking at curr_ep->id which is "item1". */
                    curr_ep = curr_ep->next;
                }
                else {
                    /* We have now found a matching parent ep */
                    cursor = p-id+1; // one past the last match
                    p = memchr(&id[cursor], '.', id_len-(p-id)-1 );
                    curr_ep = curr_ep->child;
                }
                continue;
            }
        }
        curr_ep = curr_ep->next;
    }
    return MIST_ERROR;
}

enum mist_error mist_ep_full_epid(mist_ep* ep, char id_out[MIST_EPID_LEN]) {
    memset(id_out, 0, MIST_EPID_LEN);
    if (ep == NULL) { return MIST_ERROR; }
    
    mist_ep* current = ep;
    mist_ep* stack[32];
    
    int depth = 0;

    // push every ep to stack traversing to parents
    do {
        stack[depth] = current;
        current = current->parent;
        depth++;
    } while (current != NULL);
    
    char* id = &id_out[0];
    int cursor = 0;
    int i = 0;
    
    // write each ep name from stack in reverse order
    for (i=depth-1; i>=0; i--) {
        // FIXME this can overflow!
        cursor += wish_platform_sprintf( &id[cursor], "%s.", stack[i]->id);
    }
    
    // write the last "." to null character
    id_out[cursor-1] = '\0';
    
    return MIST_NO_ERROR;
}

/**
 * Indicate that the Model has changed. Anyone having issued the 'control.signals' request will thereby receive the 'model' signal.
 */
enum mist_error mist_model_changed(mist_model *model) {
    if (model == NULL || model->mist_app == NULL) {
        return MIST_ERROR;
    }

    /* Emit 'model' signal to listeners, to indicate that the model has changed */
    emit_model_changed_signal(model->mist_app);

    return MIST_NO_ERROR;
}