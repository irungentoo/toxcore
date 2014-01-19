#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Hi-resolution timer
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif

#include <winsock2.h>
#include <windows.h>
double get_time()
{
    LARGE_INTEGER t, f;
    QueryPerformanceCounter(&t);
    QueryPerformanceFrequency(&f);
    return (double)t.QuadPart / (double)f.QuadPart;
}

#else

#include <sys/time.h>
#include <sys/resource.h>

double get_time()
{
    struct timeval t;
    struct timezone tzp;
    gettimeofday(&t, &tzp);
    return t.tv_sec + t.tv_usec * 1e-6;
}

#endif

#include "../toxcore/net_crypto.h"
#include <stdlib.h>
#include <time.h>

void rand_bytes(uint8_t *b, size_t blen)
{
    size_t i;

    for (i = 0; i < blen; i++) {
        b[i] = rand();
    }
}

int main(int argc, char *argv[])
{
    const int numtrials = 10000;

    unsigned char pk1[crypto_box_PUBLICKEYBYTES];
    unsigned char sk1[crypto_box_SECRETKEYBYTES];
    unsigned char pk2[crypto_box_PUBLICKEYBYTES];
    unsigned char sk2[crypto_box_SECRETKEYBYTES];
    unsigned char k1[crypto_box_BEFORENMBYTES];
    unsigned char k2[crypto_box_BEFORENMBYTES];

    unsigned char n[crypto_box_NONCEBYTES];

    unsigned char m[500];
    unsigned char c[sizeof(m) + crypto_box_MACBYTES];

    unsigned char k[crypto_box_BEFORENMBYTES];

    int trialno;

    double starttime;
    double endtime;
    double slow_time;
    double fast_time;
    double keygen_time;
    double precompute_time;

    // Pregenerate
    crypto_box_keypair(pk1, sk1);
    crypto_box_keypair(pk2, sk2);
    encrypt_precompute(pk1, sk2, k1);
    encrypt_precompute(pk2, sk1, k2);
    rand_bytes(m, sizeof(m));
    rand_bytes(n, sizeof(n));

    printf("starting slow...\n");
    starttime = get_time();

    for (trialno = 0; trialno < numtrials; trialno++) {
        encrypt_data(pk1, sk2, n, m, sizeof(m), c);
        decrypt_data(pk2, sk1, n, c, sizeof(c), m);
    }

    endtime = get_time();
    slow_time = endtime - starttime;

    printf("starting fast...\n");
    starttime = get_time();

    for (trialno = 0; trialno < numtrials; trialno++) {
        encrypt_data_fast(k1, n, m, sizeof(m), c);
        decrypt_data_fast(k2, n, c, sizeof(c), m);
    }

    endtime = get_time();
    fast_time = endtime - starttime;

    printf("starting keygen...\n");
    starttime = get_time();

    for (trialno = 0; trialno < numtrials; trialno++) {
        crypto_box_keypair(pk1, sk1);
        crypto_box_keypair(pk2, sk2);
    }

    endtime = get_time();
    keygen_time = endtime - starttime;

    printf("starting precompute...\n");
    starttime = get_time();

    for (trialno = 0; trialno < numtrials; trialno++) {
        encrypt_precompute(pk1, sk2, k);
        encrypt_precompute(pk2, sk1, k);
    }

    endtime = get_time();
    precompute_time = endtime - starttime;

    printf("\n");
    printf("trials: %i\n", 2 * numtrials);
    printf("\n");
    printf("slow time: %f sec\n", slow_time);
    printf("fast time: %f sec\n", fast_time);
    printf("keygen time: %f sec\n", keygen_time);
    printf("precompute time: %f sec\n", precompute_time);
    printf("\n");
    printf("Speed boost: %.1f%%\n", slow_time * 100 / fast_time);
    printf("\n");
    printf("slow: %.1f per second\n", 2 * numtrials / slow_time);
    printf("fast: %.1f per second\n", 2 * numtrials / fast_time);

    return 0;
}
