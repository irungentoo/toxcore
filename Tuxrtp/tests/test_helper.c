/*   test_helper.c
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

#include "test_helper.h"


arg_t* parse_args ( int argc, char* argv[] )
    {
    arg_t* _list;

    if ( argc == 1 ) {
            return NULL;
            }

    ALLOCATOR_LIST_D ( _list, arg_t, NULL )
    arg_t* it = _list;

    for ( size_t val = 0; val < argc; val ++ ) {
            it->value = argv[val];

            if ( val < argc - 1 ) { /* just about to end */
                    ALLOCATOR_LIST_NEXT_D ( it, arg_t )
                    }
            }

    return _list;
    }

int find_arg_simple ( arg_t* _head, const char* _id )
    {
    arg_t* it = _head;

    for ( int i = 1; it != NULL; it = it->next ) {
            if ( strcmp ( _id, it->value ) == 0 ) {
                    return i;
                    }

            i++;
            }

    return FAILURE;
    }

const char* find_arg_duble ( arg_t* _head, const char* _id )
    {
    for ( arg_t* it = _head; it != NULL; it = it->next ) {
            if ( strcmp ( _id, it->value ) == 0 ) {
                    if ( it->next && it->next->value[0] != '-' ) { /* exclude option */
                            return it->next->value;
                            }
                    else {
                            return NULL;
                            }
                    }
            }

    return NULL;
    }

