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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mist_follow.h"
#include "mist_model.h"
#include "wish_debug.h"
#include "mist_handler.h"
#include "bson.h"
#include "mist_mapping.h"

static char* mist_ep_path(mist_ep* ep) {
    mist_ep* elt = ep;
    
    // TODO fix this! Will break if path is larger than allocated size, and if stack is exceeded
    char* path = wish_platform_malloc(256);
    if (path == NULL) { return NULL; }
    memset(path, 0, 256);

    int i = 0;
    mist_ep* stack[10];
    for (i=0; i<10; i++) {
        stack[i] = NULL;
    }
    
    char* cursor = path;
    
    i = 0;
    
    do {
        stack[i] = elt;
        //WISHDEBUG(LOG_CRITICAL, "Add to stack %p (%i)", elt, i);
        elt = elt->parent;
        i++;
    } while (elt != NULL);
    
    while (i > 0) {
        i--;
        elt = stack[i];
        //WISHDEBUG(LOG_CRITICAL, "Pop from stack %p (%i)", elt, i);
        
        strcpy(cursor, elt->id);
        cursor += strlen(elt->id);
        
        if (i > 0) {
            *cursor = '.';
            cursor++;
        }        
    }
    
    return path;
}
