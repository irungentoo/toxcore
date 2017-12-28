#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#elif defined (__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif
