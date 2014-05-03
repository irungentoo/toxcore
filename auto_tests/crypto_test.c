#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/net_crypto.h"
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

void rand_bytes(uint8_t *b, size_t blen)
{
    size_t i;

    for (i = 0; i < blen; i++) {
        b[i] = rand();
    }
}

// These test vectors are from libsodium's test suite

unsigned char alicesk[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

unsigned char bobpk[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

unsigned char nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

unsigned char test_m[131] = {
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

unsigned char test_c[147] = {
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

START_TEST(test_known)
{
    unsigned char c[147];
    unsigned char m[131];
    int clen, mlen;

    ck_assert_msg(sizeof(c) == sizeof(m) + crypto_box_MACBYTES * sizeof(unsigned char),
                  "cyphertext should be crypto_box_MACBYTES bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    clen = encrypt_data(bobpk, alicesk, nonce, test_m, sizeof(test_m) / sizeof(unsigned char), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(unsigned char), "wrong ciphertext length");

    mlen = decrypt_data(bobpk, alicesk, nonce, test_c, sizeof(test_c) / sizeof(unsigned char), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(unsigned char), "wrong plaintext length");
}
END_TEST

START_TEST(test_fast_known)
{
    unsigned char k[crypto_box_BEFORENMBYTES];
    unsigned char c[147];
    unsigned char m[131];
    int clen, mlen;

    encrypt_precompute(bobpk, alicesk, k);

    ck_assert_msg(sizeof(c) == sizeof(m) + crypto_box_MACBYTES * sizeof(unsigned char),
                  "cyphertext should be crypto_box_MACBYTES bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    clen = encrypt_data_symmetric(k, nonce, test_m, sizeof(test_m) / sizeof(unsigned char), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(unsigned char), "wrong ciphertext length");

    mlen = decrypt_data_symmetric(k, nonce, test_c, sizeof(test_c) / sizeof(unsigned char), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(unsigned char), "wrong plaintext length");

}
END_TEST

START_TEST(test_endtoend)
{
    unsigned char pk1[crypto_box_PUBLICKEYBYTES];
    unsigned char sk1[crypto_box_SECRETKEYBYTES];
    unsigned char pk2[crypto_box_PUBLICKEYBYTES];
    unsigned char sk2[crypto_box_SECRETKEYBYTES];
    unsigned char k1[crypto_box_BEFORENMBYTES];
    unsigned char k2[crypto_box_BEFORENMBYTES];

    unsigned char n[crypto_box_NONCEBYTES];

    unsigned char m[500];
    unsigned char c1[sizeof(m) + crypto_box_MACBYTES];
    unsigned char c2[sizeof(m) + crypto_box_MACBYTES];
    unsigned char c3[sizeof(m) + crypto_box_MACBYTES];
    unsigned char c4[sizeof(m) + crypto_box_MACBYTES];
    unsigned char m1[sizeof(m)];
    unsigned char m2[sizeof(m)];
    unsigned char m3[sizeof(m)];
    unsigned char m4[sizeof(m)];

    int mlen;
    int c1len, c2len, c3len, c4len;
    int m1len, m2len, m3len, m4len;

    int testno;

    // Test 100 random messages and keypairs
    for (testno = 0; testno < 100; testno++) {
        //Generate random message (random length from 100 to 500)
        mlen = (rand() % 400) + 100;
        rand_bytes(m, mlen);
        rand_bytes(n, crypto_box_NONCEBYTES);

        //Generate keypairs
        crypto_box_keypair(pk1, sk1);
        crypto_box_keypair(pk2, sk2);

        //Precompute shared keys
        encrypt_precompute(pk2, sk1, k1);
        encrypt_precompute(pk1, sk2, k2);

        ck_assert_msg(memcmp(k1, k2, crypto_box_BEFORENMBYTES) == 0, "encrypt_precompute: bad");

        //Encrypt all four ways
        c1len = encrypt_data(pk2, sk1, n, m, mlen, c1);
        c2len = encrypt_data(pk1, sk2, n, m, mlen, c2);
        c3len = encrypt_data_symmetric(k1, n, m, mlen, c3);
        c4len = encrypt_data_symmetric(k2, n, m, mlen, c4);

        ck_assert_msg(c1len == c2len && c1len == c3len && c1len == c4len, "cyphertext lengths differ");
        ck_assert_msg(c1len == mlen + (int)crypto_box_MACBYTES, "wrong cyphertext length");
        ck_assert_msg(memcmp(c1, c2, c1len) == 0 && memcmp(c1, c3, c1len) == 0
                      && memcmp(c1, c4, c1len) == 0, "crypertexts differ");

        //Decrypt all four ways
        m1len = decrypt_data(pk2, sk1, n, c1, c1len, m1);
        m2len = decrypt_data(pk1, sk2, n, c1, c1len, m2);
        m3len = decrypt_data_symmetric(k1, n, c1, c1len, m3);
        m4len = decrypt_data_symmetric(k2, n, c1, c1len, m4);

        ck_assert_msg(m1len == m2len && m1len == m3len && m1len == m4len, "decrypted text lengths differ");
        ck_assert_msg(m1len == mlen, "wrong decrypted text length");
        ck_assert_msg(memcmp(m1, m2, mlen) == 0 && memcmp(m1, m3, mlen) == 0
                      && memcmp(m1, m4, mlen) == 0, "decrypted texts differ");
        ck_assert_msg(memcmp(m1, m, mlen) == 0, "wrong decrypted text");
    }
}
END_TEST

START_TEST(test_large_data)
{
    unsigned char k[crypto_box_BEFORENMBYTES];

    unsigned char n[crypto_box_NONCEBYTES];

    unsigned char m1[MAX_CRYPTO_PACKET_SIZE - crypto_box_MACBYTES];
    unsigned char c1[sizeof(m1) + crypto_box_MACBYTES];
    unsigned char m1prime[sizeof(m1)];

    unsigned char m2[MAX_CRYPTO_PACKET_SIZE];
    unsigned char c2[sizeof(m2) + crypto_box_MACBYTES];

    int c1len, c2len;
    int m1plen;

    //Generate random messages
    rand_bytes(m1, sizeof(m1));
    rand_bytes(m2, sizeof(m2));
    rand_bytes(n, crypto_box_NONCEBYTES);

    //Generate key
    rand_bytes(k, crypto_box_BEFORENMBYTES);

    c1len = encrypt_data_symmetric(k, n, m1, sizeof(m1), c1);
    c2len = encrypt_data_symmetric(k, n, m2, sizeof(m2), c2);

    ck_assert_msg(c1len == sizeof(m1) + crypto_box_MACBYTES, "could not encrypt");
    ck_assert_msg(c2len == sizeof(m2) + crypto_box_MACBYTES, "could not encrypt");

    m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == sizeof(m1), "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, sizeof(m1)) == 0, "decrypted texts differ");
}
END_TEST

START_TEST(test_large_data_symmetric)
{
    unsigned char k[crypto_box_KEYBYTES];

    unsigned char n[crypto_box_NONCEBYTES];

    unsigned char m1[16 * 16 * 16];
    unsigned char c1[sizeof(m1) + crypto_box_MACBYTES];
    unsigned char m1prime[sizeof(m1)];

    int c1len;
    int m1plen;

    //Generate random messages
    rand_bytes(m1, sizeof(m1));
    rand_bytes(n, crypto_box_NONCEBYTES);

    //Generate key
    new_symmetric_key(k);

    c1len = encrypt_data_symmetric(k, n, m1, sizeof(m1), c1);
    ck_assert_msg(c1len == sizeof(m1) + crypto_box_MACBYTES, "could not encrypt data");

    m1plen = decrypt_data_symmetric(k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == sizeof(m1), "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, sizeof(m1)) == 0, "decrypted texts differ");
}
END_TEST


#define DEFTESTCASE(NAME) \
    TCase *NAME = tcase_create(#NAME); \
    tcase_add_test(NAME, test_##NAME); \
    suite_add_tcase(s, NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(NAME, TIMEOUT);

Suite *crypto_suite(void)
{
    Suite *s = suite_create("Crypto");

    DEFTESTCASE(known);
    DEFTESTCASE(fast_known);
    DEFTESTCASE_SLOW(endtoend, 15); /* waiting up to 15 seconds */
    DEFTESTCASE(large_data);
    DEFTESTCASE(large_data_symmetric);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *crypto = crypto_suite();
    SRunner *test_runner = srunner_create(crypto);
    int number_failed = 0;

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
