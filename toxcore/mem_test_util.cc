#include "mem_test_util.hh"

#include <cstdlib>

#include "mem.h"
#include "test_util.hh"

Memory_Funcs const Memory_Class::vtable = {
    Method<mem_malloc_cb, Memory_Class>::invoke<&Memory_Class::malloc>,
    Method<mem_calloc_cb, Memory_Class>::invoke<&Memory_Class::calloc>,
    Method<mem_realloc_cb, Memory_Class>::invoke<&Memory_Class::realloc>,
    Method<mem_free_cb, Memory_Class>::invoke<&Memory_Class::free>,
};

Memory_Class::~Memory_Class() = default;

void *Test_Memory::malloc(void *obj, uint32_t size) { return mem->funcs->malloc(mem->obj, size); }

void *Test_Memory::calloc(void *obj, uint32_t nmemb, uint32_t size)
{
    return mem->funcs->calloc(mem->obj, nmemb, size);
}

void *Test_Memory::realloc(void *obj, void *ptr, uint32_t size)
{
    return mem->funcs->realloc(mem->obj, ptr, size);
}

void Test_Memory::free(void *obj, void *ptr) { return mem->funcs->free(mem->obj, ptr); }
