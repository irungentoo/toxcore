#include "methods.h"

#include "util.h"

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/net_crypto.h"

char const *const failure       = "Failure";
char const *const pending       = "Pending";
char const *const unimplemented = "Unimplemented";

METHOD(array, Box, encrypt)
{
    return pending;
}

METHOD(array, Box, decrypt)
{
    return pending;
}

METHOD(array, CombinedKey, precompute)
{
    return pending;
}

METHOD(array, KeyPair, newKeyPair)
{
    uint8_t key1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t key2[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(key1, key2);

    SUCCESS {
        // init array
        msgpack_pack_array(res, 2);
        msgpack_pack_bin(res, CRYPTO_PUBLIC_KEY_SIZE);
        msgpack_pack_bin_body(res, key1, CRYPTO_PUBLIC_KEY_SIZE);

        msgpack_pack_bin(res, CRYPTO_SECRET_KEY_SIZE);
        msgpack_pack_bin_body(res, key2, CRYPTO_SECRET_KEY_SIZE);
    }
    return 0;
}

METHOD(array, KeyPair, fromSecretKey)
{
    CHECK_SIZE(args, 1);
    CHECK_TYPE(args.ptr[0], MSGPACK_OBJECT_BIN);
    CHECK_SIZE(args.ptr[0].via.bin, CRYPTO_SECRET_KEY_SIZE);

    Net_Crypto c;
    uint8_t    secret_key[CRYPTO_SECRET_KEY_SIZE];
    memcpy(secret_key, args.ptr[0].via.bin.ptr, CRYPTO_SECRET_KEY_SIZE);
    load_secret_key(&c, secret_key);

    SUCCESS {
        msgpack_pack_array(res, 2);

        msgpack_pack_bin(res, CRYPTO_PUBLIC_KEY_SIZE);
        msgpack_pack_bin_body(res, c.self_secret_key, CRYPTO_PUBLIC_KEY_SIZE);
        msgpack_pack_bin(res, CRYPTO_SECRET_KEY_SIZE);
        msgpack_pack_bin_body(res, c.self_public_key, CRYPTO_SECRET_KEY_SIZE);
    }
    return 0;
}

METHOD(array, Nonce, newNonce)
{
    uint8_t nonce[24] = {0};
    random_nonce(nonce);

    SUCCESS {
        msgpack_pack_bin(res, sizeof nonce);
        msgpack_pack_bin_body(res, nonce, sizeof nonce);
    }

    return 0;
}

METHOD(array, Nonce, increment)
{
    CHECK_SIZE(args, 1);
    CHECK_TYPE(args.ptr[0], MSGPACK_OBJECT_BIN);
    CHECK_SIZE(args.ptr[0].via.bin, 24);

    uint8_t nonce[24];
    memcpy(nonce, args.ptr[0].via.bin.ptr, 24);
    increment_nonce(nonce);

    SUCCESS {
        msgpack_pack_bin(res, sizeof nonce);
        msgpack_pack_bin_body(res, nonce, sizeof nonce);
    }

    return 0;
}

METHOD(array, rpc, capabilities)
{
    return pending;
}

char const *call_method(msgpack_object_str name, msgpack_object_array args, msgpack_packer *res)
{
#define DISPATCH(SERVICE, NAME)                                                                    \
  if (name.size == sizeof #SERVICE "." #NAME - 1 &&                                                \
      memcmp(name.ptr, #SERVICE "." #NAME, name.size) == 0)                                        \
  return SERVICE##_##NAME(args, res)
    DISPATCH(Binary, decode);
    DISPATCH(Binary, encode);
    DISPATCH(Box, decrypt);
    DISPATCH(Box, encrypt);
    DISPATCH(CombinedKey, precompute);
    DISPATCH(KeyPair, fromSecretKey);
    DISPATCH(KeyPair, newKeyPair);
    DISPATCH(Nonce, increment);
    DISPATCH(Nonce, newNonce);
#undef DISPATCH

    // Default action: "Unimplemented" exception. New tests should be added here
    // returning "Pending" until they are properly implemented.
    return unimplemented;
}

int method_cmp(char const *ptr, char const *expected, size_t max_size)
{
    char *transformed = malloc(max_size);

    if (transformed == NULL) {
        return memcmp(ptr, expected, max_size);
    }

    memcpy(transformed, ptr, max_size);
    size_t i;

    for (i = 0; i < max_size; i++) {
        switch (transformed[i]) {
            case '(':
            case ')':
            case ' ':
                transformed[i] = '_';
                break;
        }
    }

    int result = memcmp(transformed, expected, max_size);

    free(transformed);

    return result;
}
