/* Public key cracker.
 *
 * Can be used to find public keys starting with specific hex (ABCD) for example.
 *
 * NOTE: There's probably a way to make this faster.
 *
 * Usage: ./cracker ABCDEF
 *
 * Will try to find a public key starting with: ABCDEF
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Sodium includes*/
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/randombytes.h>

/* NULL compatibility macro */
#include "../../toxcore/ccompat.h"

#define KEY_LEN 32
// Maximum number of bytes this program can crack in one run
#define MAX_CRACK_BYTES 8
// Maximum length of hex encoded prefix
#define MAX_HEX_PREFIX_LEN (MAX_CRACK_BYTES * 2)

#if defined(_OPENMP)
#include <omp.h>
#define NUM_THREADS() ((unsigned) omp_get_max_threads())
#else
#define NUM_THREADS() (1U)
#endif

static void print_key(const uint8_t *client_id)
{
    for (uint32_t j = 0; j < 32; ++j) {
        printf("%02X", client_id[j]);
    }
}

/// bytes needs to be at least (hex_len+1)/2 long
static size_t hex_string_to_bin(const char *hex_string, size_t hex_len, uint8_t *bytes)
{
    size_t i;
    const char *pos = hex_string;
    // make even

    for (i = 0; i < hex_len / 2; ++i, pos += 2) {
        uint8_t val;

        if (sscanf(pos, "%02hhx", &val) != 1) {
            return 0;
        }

        bytes[i] = val;
    }

    if (i * 2 < hex_len) {
        uint8_t val;

        if (sscanf(pos, "%hhx", &val) != 1) {
            return 0;
        }

        bytes[i] = (uint8_t)(val << 4);
        ++i;
    }

    return i;
}

static size_t match_hex_prefix(const uint8_t *key, const uint8_t *prefix, size_t prefix_len)
{
    size_t same = 0;
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < prefix_len / 2; ++i) {
        diff = key[i] ^ prefix[i];

        // First check high nibble
        if ((diff & 0xF0) == 0) {
            ++same;
        }

        // Then low nibble
        if (diff == 0) {
            ++same;
        } else {
            break;
        }
    }

    // check last high nibble
    if ((prefix_len % 2) && diff == 0) {
        diff = key[i] ^ prefix[i];

        // First check high nibble
        if ((diff & 0xF0) == 0) {
            ++same;
        }
    }

    return same;
}

static void cracker_core(uint64_t range_start, uint64_t range_end, uint64_t range_offs, uint64_t priv_key_shadow[4],
                         uint32_t *longest_match, uint8_t hex_prefix[MAX_CRACK_BYTES], size_t prefix_chars_len)
{
    #pragma omp parallel for firstprivate(priv_key_shadow) shared(longest_match, range_start, range_end, range_offs, hex_prefix, prefix_chars_len) schedule(static) default(none)

    for (uint64_t batch = range_start; batch < range_end; ++batch) {
        uint8_t *priv_key = (uint8_t *) priv_key_shadow;
        /*
         * We can't use the first and last bytes because they are masked in
         * curve25519. Offset by 16 bytes to get better alignment.
         */
        uint64_t *counter = priv_key_shadow + 2;
        /*
         * Add to `counter` instead of assign here, to preservere more randomness on short runs
         * There can be an intentional overflow in `batch + range_offs`
         */
        *counter += batch + range_offs;
        uint8_t pub_key[KEY_LEN] = {0};

        crypto_scalarmult_curve25519_base(pub_key, priv_key);

        const unsigned matching = (unsigned) match_hex_prefix(pub_key, hex_prefix, prefix_chars_len);

        // Global compare and update
        uint32_t l_longest_match;
        #pragma omp atomic read
        l_longest_match = *longest_match;

        if (matching > l_longest_match) {
            #pragma omp atomic write
            *longest_match = matching;

            #pragma omp critical
            {
                printf("%u chars matching: \n", matching);
                printf("Public key: ");
                print_key(pub_key);
                printf("\nSecret key: ");
                print_key(priv_key);
                printf("\n");
            }
        }
    }
}

static void print_stats(double seconds_passed, double keys_tried)
{
    printf("Runtime: %10lus, Keys tried %e/%e, Calculating %e keys/s\n",
           (unsigned long) seconds_passed, keys_tried, (double) UINT64_MAX, keys_tried / seconds_passed);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: ./cracker public_key(or beginning of one in hex format)\n");
        return 0;
    }

    const size_t prefix_chars_len = strlen(argv[1]);

    /*
     * If you can afford the hardware to crack longer prefixes, you can probably
     * afford to rewrite this program.
     */
    if (prefix_chars_len > MAX_HEX_PREFIX_LEN) {
        printf("Finding a key with more than 16 hex chars as prefix is not supported\n");
        return 1;
    }

    uint8_t hex_prefix[MAX_CRACK_BYTES] = {0};

    const size_t prefix_len = hex_string_to_bin(argv[1], prefix_chars_len, hex_prefix);

    if (prefix_len == 0) {
        printf("Invalid hex key specified\n");
        return 1;
    }

    printf("Searching for key with prefix: %s\n", argv[1]);

    time_t start_time = time(nullptr);

    // Declare private key bytes as uint64_t[4] so we can lower the alignment without problems
    uint64_t priv_key_shadow[KEY_LEN / 8];
    uint8_t *priv_key = (uint8_t *) priv_key_shadow;
    //  Put randomness into the key
    randombytes(priv_key, KEY_LEN);
    uint32_t longest_match = 0;

    // Finishes a batch every ~10s on my PC
    const uint64_t batch_size = (UINT64_C(1) << 18) * NUM_THREADS();

    // calculate remaining batch that doesn't fit the main loop
    const uint64_t rem_batch_size = UINT64_MAX % batch_size;

    const uint64_t rem_start = UINT64_MAX - rem_batch_size - 1;

    cracker_core(rem_start, UINT64_MAX, 1, priv_key_shadow, &longest_match, hex_prefix, prefix_chars_len);

    double seconds_passed = difftime(time(nullptr), start_time);
    double old_seconds_passed = seconds_passed;

    // Reduce time to first stats output
    print_stats(seconds_passed, rem_batch_size + 1);

    if (longest_match >= prefix_chars_len) {
        printf("Found matching prefix, exiting...\n");
        return 0;
    }

    for (uint64_t tries = 0; tries < rem_start; tries += batch_size) {
        cracker_core(tries, tries + batch_size, 0, priv_key_shadow, &longest_match, hex_prefix, prefix_chars_len);

        seconds_passed = difftime(time(nullptr), start_time);
        // Use double type to avoid overflow in addition, we don't need precision here anyway
        double keys_tried = ((double) tries) + rem_batch_size + 1;

        if (longest_match >= prefix_chars_len) {
            print_stats(seconds_passed, keys_tried);
            printf("Found matching prefix, exiting...\n");
            return 0;
        }

        // Rate limit output
        if (seconds_passed - old_seconds_passed > 5.0) {
            old_seconds_passed = seconds_passed;
            print_stats(seconds_passed, keys_tried);
            fflush(stdout);
        }
    }

    printf("Congrats future person who successfully searched a key space of 2^64\n");
    uint64_t *counter = priv_key_shadow + 2;
    *counter = 0;
    printf("Didn't find anything from:\n");
    print_key(priv_key);
    printf("\nto:\n");
    *counter = UINT64_MAX;
    print_key(priv_key);
    printf("\n");
    return 2;
}
