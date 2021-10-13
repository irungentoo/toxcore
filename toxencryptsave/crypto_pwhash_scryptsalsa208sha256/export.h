#ifndef C_TOXCORE_TOXENCRYPTSAVE_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_EXPORT_H
#define C_TOXCORE_TOXENCRYPTSAVE_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_EXPORT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef  VANILLA_NACL /* toxcore only uses this when libsodium is unavailable */

#ifndef __SODIUM_EXPORT_H__
#define __SODIUM_EXPORT_H__

#ifndef __GNUC__
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#ifdef SODIUM_STATIC
# define SODIUM_EXPORT
#else
# if defined(_MSC_VER)
#  ifdef DLL_EXPORT
#   define SODIUM_EXPORT __declspec(dllexport)
#  else
#   define SODIUM_EXPORT __declspec(dllimport)
#  endif
# else
#  if defined(__SUNPRO_C)
#   define SODIUM_EXPORT __attribute__ __global
#  elif defined(_MSG_VER)
#   define SODIUM_EXPORT extern __declspec(dllexport)
#  else
#   define SODIUM_EXPORT __attribute__ ((visibility ("default")))
#  endif
# endif
#endif

#endif

#endif

#endif
