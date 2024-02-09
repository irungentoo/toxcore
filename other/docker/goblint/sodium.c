#include <sodium.h>

#include <string.h>

int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, const unsigned char *seed)
{
    memset(pk, 0, 32);
    memset(sk, 0, 32);
    return 0;
}
int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
        const unsigned char *ed25519_pk)
{
    memset(curve25519_pk, 0, 32);
    return 0;
}
int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
        const unsigned char *ed25519_sk)
{
    memset(curve25519_sk, 0, 32);
    return 0;
}
void sodium_memzero(void *const pnt, const size_t len)
{
    memset(pnt, 0, len);
}
int sodium_mlock(void *const addr, const size_t len)
{
    return 0;
}
int sodium_munlock(void *const addr, const size_t len)
{
    return 0;
}
int crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    return memcmp(x, y, 32);
}
int crypto_verify_64(const unsigned char *x, const unsigned char *y)
{
    return memcmp(x, y, 64);
}
int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk)
{
    return 0;
}
int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk)
{
    return 0;
}
int crypto_box_beforenm(unsigned char *k, const unsigned char *pk,
                        const unsigned char *sk)
{
    memset(k, 0, 32);
    return 0;
}
int crypto_box_afternm(unsigned char *c, const unsigned char *m,
                       unsigned long long mlen, const unsigned char *n,
                       const unsigned char *k)
{
    memset(c, 0, 32);
    return 0;
}
int crypto_box_open_afternm(unsigned char *m, const unsigned char *c,
                            unsigned long long clen, const unsigned char *n,
                            const unsigned char *k)
{
    return 0;
}
int crypto_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n)
{
    memset(q, 0, 32);
    return 0;
}
int crypto_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k)
{
    return 0;
}
int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k)
{
    return 0;
}
int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen)
{
    return 0;
}
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen)
{
    return 0;
}
void randombytes(unsigned char *const buf, const unsigned long long buf_len)
{
    memset(buf, 0, buf_len);
}
uint32_t randombytes_uniform(const uint32_t upper_bound)
{
    return upper_bound;
}
int sodium_init(void)
{
    return 0;
}
