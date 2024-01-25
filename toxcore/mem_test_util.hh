#ifndef C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H

#include "mem.h"
#include "test_util.hh"

struct Memory_Class {
    static Memory_Funcs const vtable;
    Memory const self;

    operator Memory const *() const { return &self; }

    Memory_Class(Memory_Class const &) = default;
    Memory_Class()
        : self{&vtable, this}
    {
    }

    virtual ~Memory_Class();
    virtual mem_malloc_cb malloc = 0;
    virtual mem_calloc_cb calloc = 0;
    virtual mem_realloc_cb realloc = 0;
    virtual mem_free_cb free = 0;
};

/**
 * Base test Memory class that just forwards to os_memory. Can be
 * subclassed to override individual (or all) functions.
 */
class Test_Memory : public Memory_Class {
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());

    void *malloc(void *obj, uint32_t size) override;
    void *calloc(void *obj, uint32_t nmemb, uint32_t size) override;
    void *realloc(void *obj, void *ptr, uint32_t size) override;
    void free(void *obj, void *ptr) override;
};

#endif  // C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H
