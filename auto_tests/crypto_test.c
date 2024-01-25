#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/net_crypto.h"
#include "check_compat.h"

static void rand_bytes(const Random *rng, uint8_t *b, size_t blen)
{
    for (size_t i = 0; i < blen; i++) {
        b[i] = random_u08(rng);
    }
}

// These test vectors are from libsodium's test suite

static const uint8_t alicesk[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t bobpk[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t test_nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

static const uint8_t test_m[131] = {
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
    0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
    0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
    0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
    0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
    0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05
};

static const uint8_t test_c[147] = {
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
    0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
    0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
    0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
    0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
    0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
    0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
    0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
    0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
    0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
    0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
    0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
    0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
};

static void test_known(void)
{
    uint8_t c[147];
    uint8_t m[131];

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    const uint16_t clen = encrypt_data(bobpk, alicesk, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    const uint16_t mlen = decrypt_data(bobpk, alicesk, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static void test_fast_known(void)
{
    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t c[147];
    uint8_t m[131];

    encrypt_precompute(bobpk, alicesk, k);

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    const uint16_t clen = encrypt_data_symmetric(k, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    const uint16_t mlen = decrypt_data_symmetric(k, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static void test_endtoend(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    // Test 100 random messages and keypairs
    for (uint8_t testno = 0; testno < 100; testno++) {
        uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
        uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t sk2[CRYPTO_SECRET_KEY_SIZE];
        uint8_t k1[CRYPTO_SHARED_KEY_SIZE];
        uint8_t k2[CRYPTO_SHARED_KEY_SIZE];

        uint8_t n[CRYPTO_NONCE_SIZE];

        enum { M_SIZE = 50 };
        uint8_t m[M_SIZE];
        uint8_t c1[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c2[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c3[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c4[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t m1[sizeof(m)];
        uint8_t m2[sizeof(m)];
        uint8_t m3[sizeof(m)];
        uint8_t m4[sizeof(m)];

        //Generate random message (random length from 10 to 50)
        const uint16_t mlen = (random_u32(rng) % (M_SIZE - 10)) + 10;
        rand_bytes(rng, m, mlen);
        rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

        //Generate keypairs
        crypto_new_keypair(rng, pk1, sk1);
        crypto_new_keypair(rng, pk2, sk2);

        //Precompute shared keys
        encrypt_precompute(pk2, sk1, k1);
        encrypt_precompute(pk1, sk2, k2);

        ck_assert_msg(memcmp(k1, k2, CRYPTO_SHARED_KEY_SIZE) == 0, "encrypt_precompute: bad");

        //Encrypt all four ways
        const uint16_t c1len = encrypt_data(pk2, sk1, n, m, mlen, c1);
        const uint16_t c2len = encrypt_data(pk1, sk2, n, m, mlen, c2);
        const uint16_t c3len = encrypt_data_symmetric(k1, n, m, mlen, c3);
        const uint16_t c4len = encrypt_data_symmetric(k2, n, m, mlen, c4);

        ck_assert_msg(c1len == c2len && c1len == c3len && c1len == c4len, "cyphertext lengths differ");
        ck_assert_msg(c1len == mlen + (uint16_t)CRYPTO_MAC_SIZE, "wrong cyphertext length");
        ck_assert_msg(memcmp(c1, c2, c1len) == 0 && memcmp(c1, c3, c1len) == 0
                      && memcmp(c1, c4, c1len) == 0, "crypertexts differ");

        //Decrypt all four ways
        const uint16_t m1len = decrypt_data(pk2, sk1, n, c1, c1len, m1);
        const uint16_t m2len = decrypt_data(pk1, sk2, n, c1, c1len, m2);
        const uint16_t m3len = decrypt_data_symmetric(k1, n, c1, c1len, m3);
        const uint16_t m4len = decrypt_data_symmetric(k2, n, c1, c1len, m4);

        ck_assert_msg(m1len == m2len && m1len == m3len && m1len == m4len, "decrypted text lengths differ");
        ck_assert_msg(m1len == mlen, "wrong decrypted text length");
        ck_assert_msg(memcmp(m1, m2, mlen) == 0 && memcmp(m1, m3, mlen) == 0
                      && memcmp(m1, m4, mlen) == 0, "decrypted texts differ");
        ck_assert_msg(memcmp(m1, m, mlen) == 0, "wrong decrypted text");
    }
}

static void test_large_data(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t n[CRYPTO_NONCE_SIZE];

    const size_t m1_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *m1 = (uint8_t *)malloc(m1_size);
    uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
    uint8_t *m1prime = (uint8_t *)malloc(m1_size);

    const size_t m2_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *m2 = (uint8_t *)malloc(m2_size);
    uint8_t *c2 = (uint8_t *)malloc(m2_size + CRYPTO_MAC_SIZE);

    ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr && m2 != nullptr && c2 != nullptr);

    //Generate random messages
    rand_bytes(rng, m1, m1_size);
    rand_bytes(rng, m2, m2_size);
    rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

    //Generate key
    rand_bytes(rng, k, CRYPTO_SHARED_KEY_SIZE);

    const uint16_t c1len = encrypt_data_symmetric(k, n, m1, m1_size, c1);
    const uint16_t c2len = encrypt_data_symmetric(k, n, m2, m2_size, c2);

    ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt");
    ck_assert_msg(c2len == m2_size + CRYPTO_MAC_SIZE, "could not encrypt");

    const uint16_t m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

    free(c2);
    free(m2);
    free(m1prime);
    free(c1);
    free(m1);
}

static void test_large_data_symmetric(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    uint8_t k[CRYPTO_SYMMETRIC_KEY_SIZE];

    uint8_t n[CRYPTO_NONCE_SIZE];

    const size_t m1_size = 16 * 16 * 16;
    uint8_t *m1 = (uint8_t *)malloc(m1_size);
    uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
    uint8_t *m1prime = (uint8_t *)malloc(m1_size);

    ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr);

    //Generate random messages
    rand_bytes(rng, m1, m1_size);
    rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

    //Generate key
    new_symmetric_key(rng, k);

    const uint16_t c1len = encrypt_data_symmetric(k, n, m1, m1_size, c1);
    ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt data");

    const uint16_t m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

    free(m1prime);
    free(c1);
    free(m1);
}

static void test_very_large_data(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    const uint8_t nonce[CRYPTO_NONCE_SIZE] = {0};
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, pk, sk);

    // 100 MiB of data (all zeroes, doesn't matter what's inside).
    const uint32_t plain_size = 100 * 1024 * 1024;
    uint8_t *plain = (uint8_t *)malloc(plain_size);
    uint8_t *encrypted = (uint8_t *)malloc(plain_size + CRYPTO_MAC_SIZE);

    ck_assert(plain != nullptr);
    ck_assert(encrypted != nullptr);

    encrypt_data(pk, sk, nonce, plain, plain_size, encrypted);

    free(encrypted);
    free(plain);
}

static void increment_nonce_number_cmp(uint8_t *nonce, uint32_t num)
{
    uint32_t num1 = 0;
    memcpy(&num1, nonce + (CRYPTO_NONCE_SIZE - sizeof(num1)), sizeof(num1));
    num1 = net_ntohl(num1);
    uint32_t num2 = num + num1;

    if (num2 < num1) {
        for (uint16_t i = CRYPTO_NONCE_SIZE - sizeof(num1); i != 0; --i) {
            ++nonce[i - 1];

            if (nonce[i - 1] != 0) {
                break;
            }
        }
    }

    num2 = net_htonl(num2);
    memcpy(nonce + (CRYPTO_NONCE_SIZE - sizeof(num2)), &num2, sizeof(num2));
}

static void test_increment_nonce(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    uint8_t n[CRYPTO_NONCE_SIZE];

    for (uint32_t i = 0; i < CRYPTO_NONCE_SIZE; ++i) {
        n[i] = random_u08(rng);
    }

    uint8_t n1[CRYPTO_NONCE_SIZE];

    memcpy(n1, n, CRYPTO_NONCE_SIZE);

    for (uint32_t i = 0; i < (1 << 18); ++i) {
        increment_nonce_number_cmp(n, 1);
        increment_nonce(n1);
        ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce function");
    }

    for (uint32_t i = 0; i < (1 << 18); ++i) {
        const uint32_t r = random_u32(rng);
        increment_nonce_number_cmp(n, r);
        increment_nonce_number(n1, r);
        ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce_number function");
    }
}

static void test_memzero(void)
{
    uint8_t src[sizeof(test_c)];
    memcpy(src, test_c, sizeof(test_c));

    crypto_memzero(src, sizeof(src));

    for (size_t i = 0; i < sizeof(src); i++) {
        ck_assert_msg(src[i] == 0, "Memory is not zeroed");
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_known();
    test_fast_known();
    test_endtoend(); /* waiting up to 15 seconds */
    test_large_data();
    test_large_data_symmetric();
    test_very_large_data();
    test_increment_nonce();
    test_memzero();

    return 0;
}
