#ifdef _MSC_VER
#define pid_t int
// #include <libcompat.h>
#endif
#include <check.h>
#ifdef _MSC_VER
#undef pid_t
#endif
