#include <stdint.h>

typedef int_least8_t least8;
typedef int_fast8_t fast8;

#if INT8_MAX
typedef int8_t i8;
#endif

typedef int_least16_t least16;
typedef int_fast16_t fast16;

#if INT16_MAX
typedef int16_t i16;
#endif

typedef int_least32_t least32;
typedef int_fast32_t fast32;

#if INT32_MAX
typedef int32_t i32;
#endif

typedef int_least64_t least64;
typedef int_fast64_t fast64;

#if INT64_MAX
typedef int64_t i64;
#endif

typedef uint_least8_t uleast8;
typedef uint_fast8_t ufast8;

#if UINT8_MAX
typedef uint8_t ui8;
#endif

typedef uint_least16_t uleast16;
typedef uint_fast16_t ufast16;

#if UINT16_MAX
typedef uint16_t ui16;
#endif

typedef uint_least32_t uleast32;
typedef uint_fast32_t ufast32;

#if UINT32_MAX
typedef uint32_t ui32;
#endif

typedef uint_least64_t uleast64;
typedef uint_fast64_t ufast64;

#if UINT64_MAX
typedef uint64_t ui64;
#endif
