#ifndef _ALLOCATOR_H_
#define _ALLOCATOR_H_

#include <malloc.h>

#define ALLOCATOR_VAR(VAR, TYPE, NUM) TYPE* VAR = (TYPE*)malloc(sizeof(TYPE) * NUM);
#define ALLOCATOR(VAR, TYPE, NUM) VAR=(TYPE*)malloc(sizeof(TYPE) * NUM);

#define ALLOCATOR_S(VAR, TYPE) ALLOCATOR(VAR,TYPE,1)
#define ALLOCATOR_V(VAR, TYPE) ALLOCATOR_VAR(VAR, TYPE, 1)

#define ALLOCATOR_LIST_S(VAR, TYPE, VAL) ALLOCATOR(VAR,TYPE,1) VAR->next=VAL;
#define ALLOCATOR_LIST_D(VAR, TYPE, VAL) ALLOCATOR_LIST_S(VAR, TYPE, NULL) VAR->prev=VAL;

#define ALLOCATOR_LIST_NEXT_S(VAR, TYPE)      { TYPE* p; ALLOCATOR_LIST_S(p, TYPE, NULL) VAR->next = p; VAR = p;}
#define ALLOCATOR_LIST_NEXT_D(VAR, TYPE)      { TYPE* p; ALLOCATOR_LIST_D(p, TYPE, VAR) VAR->next = p; VAR = p; }

#define DEALLOCATOR(VAR) free(VAR);

#define DEALLOCATOR_LIST(VAR, TYPE) { TYPE* _next; _next = VAR->next; do { free(VAR); VAR = _next; if ( _next ) _next = VAR->next; } while ( _next ); }


#define DYNAMIC_STRING(VAR, SIZE) { ALLOCATOR(VAR, char, SIZE) memset(VAR, '\0', SIZE); }


#define ADD_ALLOCATE(VAR, TYPE, PREV) realloc(VAR, sizeof(TYPE) * ( PREV + 1 ) );

#endif /* _ALLOCATOR_H_ */
