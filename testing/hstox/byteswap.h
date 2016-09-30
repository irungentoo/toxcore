#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif
