/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "mem.h"

#include <stdlib.h>

#include "attributes.h"
#include "ccompat.h"

nullable(1)
static void *sys_malloc(void *obj, uint32_t size)
{
    return malloc(size);
}

nullable(1)
static void *sys_calloc(void *obj, uint32_t nmemb, uint32_t size)
{
    return calloc(nmemb, size);
}

nullable(1, 2)
static void *sys_realloc(void *obj, void *ptr, uint32_t size)
{
    return realloc(ptr, size);
}

nullable(1, 2)
static void sys_free(void *obj, void *ptr)
{
    free(ptr);
}

static const Memory_Funcs os_memory_funcs = {
    sys_malloc,
    sys_calloc,
    sys_realloc,
    sys_free,
};
static const Memory os_memory_obj = {&os_memory_funcs};

const Memory *os_memory(void)
{
    return &os_memory_obj;
}

void *mem_balloc(const Memory *mem, uint32_t size)
{
    void *const ptr = mem->funcs->malloc(mem->obj, size);
    return ptr;
}

void *mem_alloc(const Memory *mem, uint32_t size)
{
    void *const ptr = mem->funcs->calloc(mem->obj, 1, size);
    return ptr;
}

void *mem_valloc(const Memory *mem, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    void *const ptr = mem->funcs->calloc(mem->obj, nmemb, size);
    return ptr;
}

void *mem_vrealloc(const Memory *mem, void *ptr, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    void *const new_ptr = mem->funcs->realloc(mem->obj, ptr, bytes);
    return new_ptr;
}

void mem_delete(const Memory *mem, void *ptr)
{
    mem->funcs->free(mem->obj, ptr);
}
