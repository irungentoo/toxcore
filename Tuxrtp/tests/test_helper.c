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

