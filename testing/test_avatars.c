/*
 * A bot to test Tox avatars
 *
 * Usage: ./test_avatars <data dir>
 *
 * Connects to the Tox network, publishes our avatar, requests our friends
 * avatars and, if available, saves them to a local cache.
 * This bot automatically accepts any friend request.
 *
 *
 * Data dir MUST have:
 *
 *  - A file named "data" (named accordingly to STS Draft v0.1.0) with
 *    user id, friends, bootstrap data, etc. from a previously configured
 *    Tox session; use a client (eg. toxic) to configure it, add friends,
 *    etc.
 *
 * Data dir MAY have:
 *
 *  - A file named avatar.png.  If given, the bot will publish it. Otherwise,
 *    no avatar will be set.
 *
 *  - A directory named "avatars" with the currently cached avatars.
 *
 *
 * The bot will answer to these commands:
 *
 *  !debug-on       - Enable extended debug messages
 *  !debug-off      - Disenable extended debug messages
 *  !set-avatar     - Set our avatar to the contents of the file avatar.*
 *  !remove-avatar  - Remove our avatar
 *
 */

#define DATA_FILE_NAME "data"
#define AVATAR_DIR_NAME "avatars"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/tox.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>



/* Basic debug utils */

#define DEBUG(format, ...) debug_printf("DEBUG: %s:%d %s: " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)

static bool print_debug_msgs = true;

static void debug_printf(const char *fmt, ...)
{
    if (print_debug_msgs == true) {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
}






/* ------------ Avatar cache managenment functions ------------ */

typedef struct {
    uint8_t format;
    char *suffix;
    char *file_name;
} def_avatar_name_t;

static const def_avatar_name_t def_avatar_names[] = {
    /* In order of preference */
    { TOX_AVATAR_FORMAT_PNG,  "png", "avatar.png" },
    { TOX_AVATAR_FORMAT_NONE, NULL, NULL },    /* Must be the last one */
};



static void set_avatar(Tox *tox, const char *base_dir);


static char *get_avatar_suffix_from_format(uint8_t format)
{
    int i;

    for (i = 0; def_avatar_names[i].format != TOX_AVATAR_FORMAT_NONE; i++)
        if (def_avatar_names[i].format == format)
            return def_avatar_names[i].suffix;

    return NULL;
}


/* Load avatar data from a file into a memory buffer 'buf'.
 * buf must have at least TOX_MAX_AVATAR_DATA_LENGTH bytes
 * Returns the length of the data sucess or < 0 on error
 */
static int load_avatar_data(char *fname, uint8_t *buf)
{
    FILE *fp = fopen(fname, "rb");

    if (fp == NULL)
        return -1;  /* Error */

    size_t n = fread(buf, 1, TOX_AVATAR_MAX_DATA_LENGTH, fp);
    int ret;

    if (ferror(fp) != 0 || n == 0)
        ret = -1;   /* Error */
    else
        ret = n;

    fclose(fp);
    return ret;
}


/* Save avatar data to a file */
static int save_avatar_data(char *fname, uint8_t *data, uint32_t len)
{
    FILE *fp = fopen(fname, "wb");

    if (fp == NULL)
        return -1;  /* Error */

    int ret = 0;    /* Ok */

    if (fwrite(data, 1, len, fp) != len)
        ret = -1;   /* Error */

    if (fclose(fp) != 0)
        ret = -1;   /* Error */

    return ret;
}


static void byte_to_hex_str(const uint8_t *buf, const size_t buflen, char *dst)
{
    const char *hex_chars = "0123456789ABCDEF";
    size_t i = 0;
    size_t j = 0;

    while (i < buflen) {
        dst[j++] = hex_chars[(buf[i] >> 4) & 0xf];
        dst[j++] = hex_chars[buf[i] & 0xf];
        i++;
    }

    dst[j++] = '\0';
}

/* Make the cache file name for a avatar of the given format for the given
 * client id.
 */
static int make_avatar_file_name(char *dst, size_t dst_len,
                                 char *base_dir, uint8_t format, uint8_t *client_id)
{
    char client_id_str[2 * TOX_CLIENT_ID_SIZE + 1];
    byte_to_hex_str(client_id, TOX_CLIENT_ID_SIZE, client_id_str);

    const char *suffix = get_avatar_suffix_from_format(format);

    if (suffix == NULL)
        return -1;  /* Error */

    int n = snprintf(dst, dst_len, "%s/%s/%s.%s", base_dir, AVATAR_DIR_NAME,
                     client_id_str, suffix);
    dst[dst_len - 1] = '\0';

    if (n >= dst_len)
        return -1;  /* Error: Output truncated */

    return 0;   /* Ok */
}


/* Load a cached avatar into the buffer 'data' (which must be at least
 * TOX_MAX_AVATAR_DATA_LENGTH bytes long). Gets the file name from client
 * id and the given data format.
 * Returns 0 on success, or -1 on error.
 */
static int load_user_avatar(Tox *tox, char *base_dir, int friendnum,
                            uint8_t format, uint8_t *hash, uint8_t *data, uint32_t *datalen)
{
    uint8_t addr[TOX_CLIENT_ID_SIZE];

    if (tox_get_client_id(tox, friendnum, addr) != 0) {
        DEBUG("Bad client id, friendnumber=%d", friendnum);
        return -1;
    }

    char path[PATH_MAX];
    int ret = make_avatar_file_name(path, sizeof(path), base_dir, format, addr);

    if (ret != 0) {
        DEBUG("Can't create an file name for this user/avatar.");
        return -1;
    }

    ret = load_avatar_data(path, data);

    if (ret < 0) {
        DEBUG("Failed to load avatar data.");
        return -1;
    }

    *datalen = ret;
    tox_hash(hash, data, *datalen);

    return 0;
}

/* Save a user avatar into the cache. Gets the file name from client id and
 * the given data format.
 * Returns 0 on success, or -1 on error.
 */
static int save_user_avatar(Tox *tox, char *base_dir, int friendnum,
                            uint8_t format, uint8_t *data, uint32_t datalen)
{
    uint8_t addr[TOX_CLIENT_ID_SIZE];

    if (tox_get_client_id(tox, friendnum, addr) != 0) {
        DEBUG("Bad client id, friendnumber=%d", friendnum);
        return -1;
    }

    char path[PATH_MAX];
    int ret = make_avatar_file_name(path, sizeof(path), base_dir, format, addr);

    if (ret != 0) {
        DEBUG("Can't create a file name for this user/avatar");
        return -1;
    }

    return save_avatar_data(path, data, datalen);
}

/* Delete all cached avatars for a given user */
static int delete_user_avatar(Tox *tox, char *base_dir, int friendnum)
{
    uint8_t addr[TOX_CLIENT_ID_SIZE];

    if (tox_get_client_id(tox, friendnum, addr) != 0) {
        DEBUG("Bad client id, friendnumber=%d", friendnum);
        return -1;
    }

    char path[PATH_MAX];

    /* This iteration is dumb and inefficient */
    int i;

    for (i = 0; def_avatar_names[i].format != TOX_AVATAR_FORMAT_NONE; i++) {
        int ret = make_avatar_file_name(path, sizeof(path), base_dir,
                                        def_avatar_names[i].format, addr);

        if (ret != 0) {
            DEBUG("Failed to create avatar path for friend #%d, format %d\n",
                  friendnum, def_avatar_names[i].format);
            continue;
        }

        if (unlink(path) == 0)
            printf("Avatar file %s deleted.\n", path);
    }

    return 0;
}




/* ------------ Protocol callbacks ------------ */

static void friend_status_cb(Tox *tox, int n, uint8_t status, void *ud)
{
    uint8_t addr[TOX_CLIENT_ID_SIZE];
    char addr_str[2 * TOX_CLIENT_ID_SIZE + 1];

    if (tox_get_client_id(tox, n, addr) == 0) {
        byte_to_hex_str(addr, TOX_CLIENT_ID_SIZE, addr_str);
        printf("Receiving status from %s: %u\n", addr_str, status);
    }
}

static void friend_avatar_info_cb(Tox *tox, int32_t n, uint8_t format, uint8_t *hash, void *ud)
{
    char *base_dir = (char *) ud;
    uint8_t addr[TOX_CLIENT_ID_SIZE];
    char addr_str[2 * TOX_CLIENT_ID_SIZE + 1];
    char hash_str[2 * TOX_HASH_LENGTH + 1];

    if (tox_get_client_id(tox, n, addr) == 0) {
        byte_to_hex_str(addr, TOX_CLIENT_ID_SIZE, addr_str);
        printf("Receiving avatar information from %s.\n", addr_str);
    } else {
        DEBUG("tox_get_client_id failed");
        printf("Receiving avatar information from friend number %u.\n", n);
    }

    byte_to_hex_str(hash, TOX_HASH_LENGTH, hash_str);
    DEBUG("format=%u, hash=%s", format, hash_str);

    if (format == TOX_AVATAR_FORMAT_NONE) {
        printf(" -> User do not have an avatar.\n");
        /* User have no avatar anymore, delete it from our cache */
        delete_user_avatar(tox, base_dir, n);
    } else {
        /* Check the hash of the currently cached user avatar
         * WARNING: THIS IS ONLY AN EXAMPLE!
         *
         * Real clients should keep the hashes in memory (eg. in the object
         * used to represent a friend in the friend list) and do not access
         * the file system or do anything resource intensive in reply of
         * these events.
         */
        uint32_t cur_av_len;
        uint8_t cur_av_data[TOX_AVATAR_MAX_DATA_LENGTH];
        uint8_t cur_av_hash[TOX_HASH_LENGTH];
        int ret;

        ret = load_user_avatar(tox, base_dir, n, format, cur_av_hash, cur_av_data, &cur_av_len);

        if (ret != 0
                && memcpy(cur_av_hash, hash, TOX_HASH_LENGTH) != 0) {
            printf(" -> Cached avatar is outdated. Requesting avatar data.\n");
            tox_request_avatar_data(tox, n);
        } else {
            printf(" -> Cached avatar is still updated.\n");
        }
    }

}

static void friend_avatar_data_cb(Tox *tox, int32_t n, uint8_t format,
                                  uint8_t *hash, uint8_t *data, uint32_t datalen, void *ud)
{
    char *base_dir = (char *) ud;
    uint8_t addr[TOX_CLIENT_ID_SIZE];
    char addr_str[2 * TOX_CLIENT_ID_SIZE + 1];
    char hash_str[2 * TOX_HASH_LENGTH + 1];

    if (tox_get_client_id(tox, n, addr) == 0) {
        byte_to_hex_str(addr, TOX_CLIENT_ID_SIZE, addr_str);
        printf("Receiving avatar data from %s.\n", addr_str);
    } else {
        DEBUG("tox_get_client_id failed");
        printf("Receiving avatar data from friend number %u.\n", n);
    }

    byte_to_hex_str(hash, TOX_HASH_LENGTH, hash_str);
    DEBUG("format=%u, datalen=%d, hash=%s\n", format, datalen, hash_str);

    delete_user_avatar(tox, base_dir, n);

    if (format != TOX_AVATAR_FORMAT_NONE) {
        int ret = save_user_avatar(tox, base_dir, n, format, data, datalen);

        if (ret == 0)
            printf(" -> Avatar updated in the cache.\n");
        else
            printf(" -> Failed to save user avatar.\n");
    }
}


static void friend_msg_cb(Tox *tox, int n, const uint8_t *msg, uint16_t len, void *ud)
{
    const char *base_dir = (char *) ud;
    const char *msg_str = (char *) msg;
    uint8_t addr[TOX_CLIENT_ID_SIZE];
    char addr_str[2 * TOX_CLIENT_ID_SIZE + 1];

    if (tox_get_client_id(tox, n, addr) == 0) {
        byte_to_hex_str(addr, TOX_FRIEND_ADDRESS_SIZE, addr_str);
        printf("Receiving message from %s:\n   %s\n", addr_str, msg);
    }

    /* Handle bot commands for the tests */
    char *reply_ptr = NULL;

    if (strstr(msg_str, "!debug-on") != NULL) {
        print_debug_msgs = true;
        reply_ptr = "Debug enabled.";
    } else if (strstr(msg_str, "!debug-off") != NULL) {
        print_debug_msgs = false;
        reply_ptr = "Debug disabled.";
    } else if (strstr(msg_str, "!set-avatar") != NULL) {
        set_avatar(tox, base_dir);
        reply_ptr = "Setting image avatar";
    } else if (strstr(msg_str, "!remove-avatar") != NULL) {
        int r = tox_set_avatar(tox, TOX_AVATAR_FORMAT_NONE, NULL, 0);
        DEBUG("tox_set_avatar returned %d", r);
        reply_ptr = "Removing avatar";
    }

    /* Add more useful commands here: add friend, etc. */

    char reply[TOX_MAX_MESSAGE_LENGTH];
    int reply_len;

    if (reply_ptr)
        reply_len = snprintf(reply, sizeof(reply), "%s", reply_ptr);
    else
        reply_len = snprintf(reply, sizeof(reply),
                             "No command found in message: %s", msg);

    reply[sizeof(reply) - 1] = '\0';
    printf(" -> Reply: %s\n", reply);
    tox_send_message(tox, n, (uint8_t *) reply, reply_len);
}


static void friend_request_cb(Tox *tox, const uint8_t *public_key,
                              const uint8_t *data, uint16_t length, void *ud)
{
    char addr_str[2 * TOX_CLIENT_ID_SIZE + 1];
    byte_to_hex_str(public_key, TOX_CLIENT_ID_SIZE, addr_str);
    printf("Accepting friend request from %s.\n   %s\n", addr_str, data);
    tox_add_friend_norequest(tox, public_key);
}


static int try_avatar_file(Tox *tox, const char *base_dir, const def_avatar_name_t *an)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", base_dir, an->file_name);
    path[sizeof(path) - 1] = '\0';

    if (n >= sizeof(path)) {
        DEBUG("error: path %s too big\n", path);
        return -1;
    }

    DEBUG("trying file %s: ", path);
    FILE *fp = fopen(path, "rb");

    if (fp != NULL) {
        uint8_t buf[2 * TOX_AVATAR_MAX_DATA_LENGTH];
        int len = fread(buf, 1, sizeof(buf), fp);

        if (len >= 0 && len <= TOX_AVATAR_MAX_DATA_LENGTH) {
            int r = tox_set_avatar(tox, an->format, buf, len);
            DEBUG("%d bytes, tox_set_avatar returned=%d", len, r);

            if (r == 0)
                printf("Setting avatar file %s\n", path);
            else
                printf("Error setting avatar file %s\n", path);
        } else if (len < 0) {
            DEBUG("read error %d", len);
        } else {
            printf("Avatar file %s if too big (more than %d bytes)",
                   path, TOX_AVATAR_MAX_DATA_LENGTH);
        }

        fclose(fp);
        return 0;
    } else {
        DEBUG("File %s not found", path);
    }

    return -1;
}


static void set_avatar(Tox *tox, const char *base_dir)
{
    int i;

    for (i = 0; i < 4; i++) {
        if (def_avatar_names[i].format == TOX_AVATAR_FORMAT_NONE) {
            tox_set_avatar(tox, TOX_AVATAR_FORMAT_NONE, NULL, 0);
            printf("No avatar file found, setting to NONE.\n");
            return;
        } else {
            if (try_avatar_file(tox, base_dir, &def_avatar_names[i]) == 0)
                return;
        }
    }

    /* Should be unreachable */
    printf("UNEXPECTED CODE PATH\n");
}


static void print_avatar_info(Tox *tox)
{
    uint8_t format;
    uint8_t data[TOX_AVATAR_MAX_DATA_LENGTH];
    uint8_t hash[TOX_HASH_LENGTH];
    uint32_t data_length;
    char hash_str[2 * TOX_HASH_LENGTH + 1];

    int ret = tox_get_self_avatar(tox, &format, data, &data_length, sizeof(data), hash);
    DEBUG("tox_get_self_avatar returned %d", ret);
    DEBUG("format: %d, data_length: %d", format, data_length);
    byte_to_hex_str(hash, TOX_HASH_LENGTH, hash_str);
    DEBUG("hash: %s", hash_str);
}


/* ------------ Initialization functions ------------ */

/* Create directory to store tha avatars. Returns 0 if it was sucessfuly
 * created or already existed. Returns -1 on error.
 */
static int create_avatar_diretory(const char *base_dir)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", base_dir, AVATAR_DIR_NAME);
    path[sizeof(path) - 1] = '\0';

    if (n >= sizeof(path))
        return -1;

    if (mkdir(path, 0755) == 0) {
        return 0;   /* Done */
    } else if (errno == EEXIST) {
        /* Check if the existing path is a directory */
        struct stat st;

        if (stat(path, &st) != 0) {
            perror("stat()ing avatar directory");
            return -1;
        }

        if (S_ISDIR(st.st_mode))
            return 0;
    }

    return -1;  /* Error */
}


static void *load_bootstrap_data(const char *base_dir, uint32_t *len)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", base_dir, DATA_FILE_NAME);
    path[sizeof(path) - 1] = '\0';

    if (n >= sizeof(path)) {
        printf("Load error: path %s too long\n", path);
        return NULL;
    }

    /* We should be using POSIX functions here, but let's try to be
     * compatible with Windows.
     */

    FILE *fp = fopen(path, "rb");

    if (fp == NULL) {
        printf("fatal error: file %s not found.\n", path);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        printf("seek fail\n");
        fclose(fp);
        return NULL;
    }

    int32_t flen = ftell(fp);

    if (flen < 8 || flen > 2e6) {
        printf("Fatal error: file %s have %u bytes. Out of acceptable range.\n", path, flen);
        fclose(fp);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        printf("seek fail\n");
        fclose(fp);
        return NULL;
    }

    void *buf = malloc(flen);

    if (buf == NULL) {
        printf("malloc failed, %u bytes", flen);
        fclose(fp);
        return NULL;
    }

    *len = fread(buf, 1, flen, fp);
    fclose(fp);

    if (*len != flen) {
        printf("fatal: %s have %u bytes, read only %u\n", path, flen, *len);
        free(buf);
        return NULL;
    }

    printf("bootstrap data loaded from %s (%u bytes)\n", path, flen);
    return buf;
}

static int save_bootstrap_data(Tox *tox, const char *base_dir)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", base_dir, DATA_FILE_NAME);
    path[sizeof(path) - 1] = '\0';

    if (n >= sizeof(path)) {
        printf("Save error: path %s too long\n", path);
        return -1;
    }

    char path_tmp[PATH_MAX];
    n = snprintf(path_tmp, sizeof(path_tmp), "%s.tmp", path);
    path_tmp[sizeof(path_tmp) - 1] = '\0';

    if (n >= sizeof(path_tmp)) {
        printf("error: path %s too long\n", path);
        return -1;
    }

    uint32_t len = tox_size(tox);

    if (len < 8 || len > 2e6) {
        printf("save data length == %u, out of acceptable range\n", len);
        return -1;
    }

    void *buf = malloc(len);

    if (buf == NULL) {
        printf("save data: malloc failed\n");
        return -1;
    }

    tox_save(tox, buf);

    FILE *fp = fopen(path_tmp, "wb");

    if (fp == NULL) {
        printf("Error saving data: can't open %s\n", path_tmp);
        free(buf);
        return -1;
    }

    if (fwrite(buf, 1, len, fp) != len) {
        printf("Error writing data to %s\n", path_tmp);
        free(buf);
        fclose(fp);
        return -1;
    }

    free(buf);

    if (fclose(fp) != 0) {
        printf("Error writing data to %s\n", path_tmp);
        return -1;
    }

    if (rename(path_tmp, path) != 0) {
        printf("Error renaming %s to %s\n", path_tmp, path);
        return -1;
    }

    printf("Bootstrap data saved to %s\n", path);
    return 0;   /* Done */
}




int main(int argc, char *argv[])
{
    int ret;

    if (argc != 2) {
        printf("usage: %s <data dir>\n", argv[0]);
        return 1;
    }

    char *base_dir = argv[1];

    if (create_avatar_diretory(base_dir) != 0)
        printf("Error creating avatar directory.\n");

    Tox *tox = tox_new(NULL);

    uint32_t len;
    void *data = load_bootstrap_data(base_dir, &len);

    if (data == NULL)
        return 1;

    ret = tox_load(tox, data, len);
    free(data);

    if (ret == 0) {
        printf("Tox initialized\n");
    } else {
        printf("Fatal: tox_load returned %d\n", ret);
        return 1;
    }

    tox_callback_connection_status(tox, friend_status_cb, NULL);
    tox_callback_friend_message(tox, friend_msg_cb, base_dir);
    tox_callback_friend_request(tox, friend_request_cb, NULL);
    tox_callback_avatar_info(tox, friend_avatar_info_cb, base_dir);
    tox_callback_avatar_data(tox, friend_avatar_data_cb, base_dir);

    uint8_t addr[TOX_FRIEND_ADDRESS_SIZE];
    char addr_str[2 * TOX_FRIEND_ADDRESS_SIZE + 1];
    tox_get_address(tox, addr);
    byte_to_hex_str(addr, TOX_FRIEND_ADDRESS_SIZE, addr_str);
    printf("Using local tox address: %s\n", addr_str);

#ifdef TEST_SET_RESET_AVATAR
    printf("Printing default avatar information:\n");
    print_avatar_info(tox);

    printf("Setting a new avatar:\n");
    set_avatar(tox, base_dir);
    print_avatar_info(tox);

    printf("Removing the avatar we just set:\n");
    tox_avatar(tox, TOX_AVATARFORMAT_NONE, NULL, 0);
    print_avatar_info(tox);

    printf("Setting that avatar again:\n");
#endif /* TEST_SET_RESET_AVATAR */

    set_avatar(tox, base_dir);
    print_avatar_info(tox);

    bool waiting = true;
    time_t last_save = time(0);

    while (1) {
        if (tox_isconnected(tox) && waiting) {
            printf("DHT connected.\n");
            waiting = false;
        }

        tox_do(tox);

        time_t now = time(0);

        if (now - last_save > 120) {
            save_bootstrap_data(tox, base_dir);
            last_save = now;
        }

        usleep(500000);
    }

    return 0;
}
