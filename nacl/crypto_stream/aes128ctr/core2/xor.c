#include "crypto_stream.h"

int crypto_stream_xor(
        unsigned char *out,
        const unsigned char *in,
        unsigned long long inlen,
        const unsigned char *n,
        const unsigned char *k
        )
{
    unsigned char d[crypto_stream_BEFORENMBYTES];
    crypto_stream_beforenm(d, k);
    crypto_stream_xor_afternm(out, in, inlen, n, d);
    return 0;
}
