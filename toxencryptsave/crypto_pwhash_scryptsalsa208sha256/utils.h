#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef  VANILLA_NACL /* toxcore only uses this when libsodium is unavailable */

#ifndef __SODIUM_UTILS_H__
#define __SODIUM_UTILS_H__

#include <stddef.h>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
# define _SODIUM_C99(X)
#else
# define _SODIUM_C99(X) X
#endif

SODIUM_EXPORT
void sodium_memzero(void * const pnt, const size_t len);

/* WARNING: sodium_memcmp() must be used to verify if two secret keys
 * are equal, in constant time.
 * It returns 0 if the keys are equal, and -1 if they differ.
 * This function is not designed for lexicographical comparisons.
 */
SODIUM_EXPORT
int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);

#ifdef __cplusplus
}
#endif

#endif

#endif
