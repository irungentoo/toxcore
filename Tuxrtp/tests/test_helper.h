/*   test_helper.h
 *
 *   Tests support. !Red!
 *
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _TEST__HELPER_
#define _TEST__HELPER_

#include "../../core/helper.h"
#include "../Allocator.h"

#define args int argc, char* argv[]


typedef struct arg_s {
    const char*   value;
    struct arg_s* next;
    struct arg_s* prev;

    } arg_t;



/* Parses arguments into d-list arg_t */
arg_t*      parse_args ( int argc, char* argv[] );

/* Get a single argument ( i.e. ./test -s |find if has 's' >> | find_arg_simple(_t, "-s") )
 * A little error checking, of course, returns FAILURE if not found and if found returns position
 * where it's found.
 */
int         find_arg_simple ( arg_t* _head, const char* _id );

/* Get a single argument ( i.e. ./test -d 127.0.0.1 |get 'd' value >> | find_arg_duble(_t, "-d") )
 * A little error checking, of course, returns NULL if not found and if found returns value
 * of that argument ( i.e. '127.0.0.1').
 */
const char* find_arg_duble ( arg_t* _head, const char* _id );

#endif // _TEST__HELPER_


