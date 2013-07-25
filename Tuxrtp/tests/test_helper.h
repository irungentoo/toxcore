#ifndef _TEST__HELPER_
#define _TEST__HELPER_

#include "../../core/helper.h"
#include "../Allocator.h"


#define _test_main()  int main ( int argc, char* argv[] )
#define _no_main()    int _main ( int argc, char* argv[] )


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


