/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

/* for CLIENT_ID_SIZE */
#include "DHT.h"

#include "util.h"

/* simplify this */
#if !defined(WIN32) && (defined(_WIN32) || defined(__WIN32__))
# define WIN32
#endif

#ifdef USE_MLOCK
# include "logger.h"
# ifdef WIN32
#  include <malloc.h>
# else
#  include <sys/mman.h>
# endif
#endif

/* don't call into system billions of times for no reason */
static uint64_t unix_time_value;
static uint64_t unix_base_time_value;

void unix_time_update()
{
    if (unix_base_time_value == 0)
        unix_base_time_value = ((uint64_t)time(NULL) - (current_time_monotonic() / 1000ULL));

    unix_time_value = (current_time_monotonic() / 1000ULL) + unix_base_time_value;
}

uint64_t unix_time()
{
    return unix_time_value;
}

int is_timeout(uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= unix_time();
}


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return memcmp(dest, src, CLIENT_ID_SIZE) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CLIENT_ID_SIZE);
    return CLIENT_ID_SIZE;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
    uint32_t i;
    uint8_t buff[numbytes];

    for (i = 0; i < numbytes; ++i) {
        buff[i] = num[numbytes - i - 1];
    }

    memcpy(num, buff, numbytes);
#endif
    return;
}

/* state load/save */
int load_state(load_state_callback_func load_state_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (!load_state_callback || !data) {
#ifdef DEBUG
        fprintf(stderr, "load_state() called with invalid args.\n");
#endif
        return -1;
    }


    uint16_t type;
    uint32_t length_sub, cookie_type;
    uint32_t size_head = sizeof(uint32_t) * 2;

    while (length >= size_head) {
        memcpy(&length_sub, data, sizeof(length_sub));
        memcpy(&cookie_type, data + sizeof(length_sub), sizeof(cookie_type));
        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
#ifdef DEBUG
            fprintf(stderr, "state file too short: %u < %u\n", length, length_sub);
#endif
            return -1;
        }

        if ((cookie_type >> 16) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
#ifdef DEBUG
            fprintf(stderr, "state file garbeled: %04hx != %04hx\n", (cookie_type >> 16), cookie_inner);
#endif
            return -1;
        }

        type = cookie_type & 0xFFFF;

        if (-1 == load_state_callback(outer, data, length_sub, type))
            return -1;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : -1;
};

/* Converts 4 bytes to uint32_t */
inline__ void bytes_to_U32(uint32_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint32_t ) *  bytes )              |
        ( ( uint32_t ) * ( bytes + 1 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 3 ) << 24 ) ;
#else
        ( ( uint32_t ) *  bytes        << 24 ) |
        ( ( uint32_t ) * ( bytes + 1 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 2 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 3 ) ) ;
#endif
}

/* Converts 2 bytes to uint16_t */
inline__ void bytes_to_U16(uint16_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint16_t ) *   bytes ) |
        ( ( uint16_t ) * ( bytes + 1 ) << 8 );
#else
        ( ( uint16_t ) *   bytes << 8 ) |
        ( ( uint16_t ) * ( bytes + 1 ) );
#endif
}

/* Convert uint32_t to byte string of size 4 */
inline__ void U32_to_bytes(uint8_t *dest, uint32_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
    *(dest + 2) = ( value >> 16 );
    *(dest + 3) = ( value >> 24 );
#else
    *(dest)     = ( value >> 24 );
    *(dest + 1) = ( value >> 16 );
    *(dest + 2) = ( value >> 8 );
    *(dest + 3) = ( value );
#endif
}

/* Convert uint16_t to byte string of size 2 */
inline__ void U16_to_bytes(uint8_t *dest, uint16_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
#else
    *(dest)     = ( value >> 8 );
    *(dest + 1) = ( value );
#endif
}

#ifdef USE_MLOCK

#ifdef WIN32
static size_t getpagesize_impl()
{
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return si.dwPageSize;
}

static void *aligned_alloc_impl(size_t length, size_t alignment)
{
  return _aligned_malloc(length, alignment);
}

static uint8_t mlock_impl(void *addr, size_t length)
{
  return VirtualLock(addr, length) != 0;
}

static uint8_t munlock_impl(void *addr, size_t length)
{
  return VirtualUnlock(addr, length) != 0;
}
#else
static size_t getpagesize_impl() {
  return getpagesize();
}

static void *aligned_alloc_impl(size_t length, size_t alignment)
{
  void *addr = NULL;
  posix_memalign(&addr, alignment, length);
  return addr;
}

static uint8_t mlock_impl(void *addr, size_t length)
{
  return mlock(addr, length) == 0;
}

static uint8_t munlock_impl(void *addr, size_t length)
{
  return munlock(addr, length) == 0;
}
#endif


typedef uint32_t usebits_t;

#define MIN_MAPSIZE (8*sizeof(usebits_t) * crypto_box_SECRETKEYBYTES)

typedef struct Locked_Map_s {
  unsigned char       *address;
  usebits_t           *used;
  struct Locked_Map_s *next;
} Locked_Map;

static size_t      pagesize  = 0;
static size_t      mapsize   = 0;
static size_t      usedcount = 0;
static Locked_Map *lockedmap = NULL;

static void delete_lockedmap(Locked_Map **map_)
{
  Locked_Map *map = *map_;
  if (map->used)
    free(map->used);
  if (map->address) {
    memset(map->address, 0, mapsize);
    munlock_impl(map->address, mapsize);
    free(map->address);
  }
  *map_ = map->next;
  free(map);
}

static Locked_Map *new_lockedmap()
{
  Locked_Map *map = calloc(1, sizeof(Locked_Map));
  if (!map)
    goto showerror;

  map->address = aligned_alloc_impl(mapsize, pagesize);
  if (!map->address) {
    free(map);
    goto showerror;
  }
  if (mlock_impl(map->address, mapsize) != 0) {
    delete_lockedmap(&map);
    goto showerror;
  }

  map->used = calloc(1, sizeof(usebits_t) * usedcount);
  if (!map->used) {
    delete_lockedmap(&map);
    goto showerror;
  }
  return map;
showerror:
  LOGGER_ERROR("failed to allocate a locked memory page\n");
  return NULL;
}

static uint8_t init_pagedata()
{
  if (!pagesize) {
    pagesize = getpagesize_impl();
    if (!pagesize) {
      /* Without a page size we're screwed */
      return 0;
    }
    while (pagesize < crypto_box_SECRETKEYBYTES)
      pagesize <<= 1;

    mapsize = pagesize;
    if (mapsize < MIN_MAPSIZE)
      mapsize = MIN_MAPSIZE;

    usedcount = mapsize / (crypto_box_SECRETKEYBYTES * 8*sizeof(usebits_t));
    if (!usedcount)
      usedcount = 1;
  }
  return 1;
}

void* alloc_secret()
{
  if (!init_pagedata())
    return NULL;

  if (!lockedmap) {
    lockedmap = new_lockedmap();
    if (!lockedmap)
      return NULL;
  }

  Locked_Map **map;
  size_t       useindex = 0;
  for (map = &lockedmap; *map; map = &(*map)->next) {
    for (useindex = 0; useindex != usedcount; ++useindex) {
      if (~(*map)->used[useindex])
        break;
    }
    if (useindex != usedcount)
      break;
  }

  if (!*map) {
    *map = new_lockedmap();
    if (!*map)
      return NULL;
    useindex = 0;
  }

  usebits_t used = (*map)->used[useindex];
  usebits_t bit  = 1;
  size_t    offset = useindex * (8*sizeof(usebits_t)) * crypto_box_SECRETKEYBYTES;
  while ((used & bit)) {
    bit <<= 1;
    offset += crypto_box_SECRETKEYBYTES;
  }

  (*map)->used[useindex] |= bit;

  return (*map)->address + offset;
}

void free_secret(void *data_)
{
  if (!data_)
    return;

  memset(data_, 0, crypto_box_SECRETKEYBYTES);

  unsigned char *data = data_;

  /* locate the map we're in */
  Locked_Map **pmap;
  for (pmap = &lockedmap; *pmap; pmap = &(*pmap)->next) {
    if (data >= (*pmap)->address && data < (*pmap)->address + mapsize)
      break;
  }

  Locked_Map *map = *pmap;
  if (!map)
    goto user_error;

  ptrdiff_t off = data - map->address;

  size_t bit = off / crypto_box_SECRETKEYBYTES;
  size_t useindex = bit / (8*sizeof(usebits_t));
  size_t usebit   = bit % (8*sizeof(usebits_t));

  if (useindex >= usedcount)
    goto user_error;

  if (!(map->used[useindex] & (1<<usebit)))
    goto double_free;

  map->used[useindex] &= ~(1<<usebit);

  for (useindex = 0; useindex != usedcount; ++useindex) {
    if (map->used[useindex])
      return;
  }

  delete_lockedmap(pmap);
  return;

user_error:
  /* User error!  */
  LOGGER_ERROR("free_secret called on non-locked memory!\n");
  free(data);
  return;
double_free:
  LOGGER_ERROR("double free_secret corruption!\n");
}

#else
void* alloc_secret()
{
  return calloc(1, crypto_box_SECRETKEYBYTES);
}

void free_secret(void *data)
{
  if (!data)
    return;
  memset(data, 0, crypto_box_SECRETKEYBYTES);
  free(data);
}
#endif
