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
#ifndef MIST_DEFS_H
#define MIST_DEFS_H

#if (defined(_WIN32) || defined(_WIN64))
#	if (defined(MIST_NODLL) || defined(MIST_STATIC))  
#		define MIST_EXPORT
#	else
#		ifdef MIST_API_EXPORTS
#			define MIST_EXPORT __declspec(dllexport)
#		else
#			define MIST_EXPORT __declspec(dllimport)
#		endif
#	endif
#else
#   if __GNUC__ >= 4
#       define MIST_EXPORT __attribute__ ((visibility("default")))
#   else
#       define MIST_EXPORT
#   endif
#endif
    

#endif /* MIST_DEFS_H */

