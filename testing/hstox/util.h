#pragma once

#include <msgpack.h>

#define check_return(err, expr)                                                                    \
  __extension__({                                                                                  \
    __typeof__(expr) _r = (expr);                                                                  \
    if (_r < 0)                                                                                    \
      return err | (__LINE__ << 16);                                                               \
    _r;                                                                                            \
  })

#define propagate(expr)                                                                            \
  do {                                                                                             \
    __typeof__(expr) _r = (expr);                                                                  \
    if (_r != E_OK)                                                                                \
      return _r;                                                                                   \
  } while (0)

char const *type_name(msgpack_object_type type);

// Statically allocated "asprintf".
char const *ssprintf(char const *fmt, ...);

int msgpack_pack_string(msgpack_packer *pk, char const *str);
int msgpack_pack_stringf(msgpack_packer *pk, char const *fmt, ...);
int msgpack_pack_vstringf(msgpack_packer *pk, char const *fmt, va_list ap);
