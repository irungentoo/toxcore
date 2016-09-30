/* Tox Sync
 *
 * Proof of concept bittorrent sync like software using tox, syncs two directories.
 *
 * Command line arguments are the ip, port and public_key of a node (for bootstrapping) and the folder to sync.
 *
 * EX: ./test 127.0.0.1 33445 CDCFD319CE3460824B33BE58FD86B8941C9585181D8FBD7C79C5721D7C2E9F7C ./sync_folder/
 *
 * NOTE: for security purposes, both tox sync instances must manually add each other as friend for it to work.
 *
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/tox.h"
#include "misc_tools.c"

#include <unistd.h>
#define c_sleep(x) usleep(1000*x)

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <stdio.h>

#define NUM_FILE_SENDERS 256
typedef struct {
    FILE *file;
    uint32_t friendnum;
    uint32_t filenumber;
} File_t;
static File_t file_senders[NUM_FILE_SENDERS];
static File_t file_recv[NUM_FILE_SENDERS];
static uint8_t numfilesenders;

static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                   size_t length,
                                   void *user_data)
{
    unsigned int i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        /* This is slow */
        if (file_senders[i].file && file_senders[i].friendnum == friend_number && file_senders[i].filenumber == file_number) {
            if (length == 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
                printf("[t] %u file transfer: %u completed\n", file_senders[i].friendnum, file_senders[i].filenumber);
                break;
            }

            fseek(file_senders[i].file, position, SEEK_SET);
            uint8_t data[length];
            int len = fread(data, 1, length, file_senders[i].file);
            tox_file_send_chunk(tox, friend_number, file_number, position, data, len, 0);
            break;
        }
    }
}


static uint32_t add_filesender(Tox *m, uint16_t friendnum, char *filename)
{
    FILE *tempfile = fopen(filename, "rb");

    if (tempfile == 0) {
        return -1;
    }

    fseek(tempfile, 0, SEEK_END);
    uint64_t filesize = ftell(tempfile);
    fseek(tempfile, 0, SEEK_SET);
    uint32_t filenum = tox_file_send(m, friendnum, TOX_FILE_KIND_DATA, filesize, 0, (uint8_t *)filename,
                                     strlen(filename), 0);

    if (filenum == -1) {
        return -1;
    }

    file_senders[numfilesenders].file = tempfile;
    file_senders[numfilesenders].friendnum = friendnum;
    file_senders[numfilesenders].filenumber = filenum;
    ++numfilesenders;
    return filenum;
}

static void kill_filesender(Tox *m, uint32_t filenum)
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        if (file_senders[i].file != 0 && file_senders[i].filenumber == filenum) {
            fclose(file_senders[i].file);
            file_senders[i].file = 0;
        }
    }
}
static int not_sending(void)
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        if (file_senders[i].file != 0) {
            return 0;
        }
    }

    return 1;
}

static char path[1024];

static void file_request_accept(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t type,
                                uint64_t file_size,
                                const uint8_t *filename, size_t filename_length, void *user_data)
{
    if (type != TOX_FILE_KIND_DATA) {
        printf("Refused invalid file type.");
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
    }

    char fullpath[1024];
    uint32_t i;
    uint16_t rm = 0;

    for (i = 0; i < strlen((const char *)filename); ++i) {
        if (filename[i] == '/') {
            rm = i;
        }
    }

    if (path[strlen(path) - 1] == '/') {
        sprintf(fullpath, "%s%s", path, filename + rm + 1);
    } else {
        sprintf(fullpath, "%s/%s", path, filename + rm + 1);
    }

    FILE *tempfile = fopen(fullpath, "rb");

    if (tempfile != 0) {
        fclose(tempfile);
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
    }

    uint8_t file_index = (file_number >> 16) - 1;
    file_recv[file_index].file = fopen(fullpath, "wb");

    if (file_recv[file_index].file == 0) {
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
    }

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, 0)) {
        printf("Accepted file transfer. (file: %s)\n", fullpath);
    }
}

static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                               void *user_data)
{
    if (file_number < (1 << 15) && (control == TOX_FILE_CONTROL_CANCEL)) {
        kill_filesender(tox, file_number);
        return;
    }

    if (file_number > (1 << 15) && (control == TOX_FILE_CONTROL_CANCEL)) {
        uint8_t file_index = (file_number >> 16) - 1;
        fclose(file_recv[file_index].file);
        printf("File closed\n");
        file_recv[file_index].file = 0;
        return;
    }
}

static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
    uint8_t file_index = (filenumber >> 16) - 1;

    if (length == 0) {
        fclose(file_recv[file_index].file);
        printf("File closed\n");
        file_recv[file_index].file = 0;
        printf("%u file transfer: %u completed\n", friendnumber, filenumber);
        return;
    }

    if (file_recv[file_index].file != 0) {
        fseek(file_recv[file_index].file, position, SEEK_SET);

        if (fwrite(data, length, 1, file_recv[file_index].file) != 1) {
            printf("Error writing data\n");
        }
    }
}

static void print_online(Tox *tox, uint32_t friendnumber, TOX_CONNECTION status, void *userdata)
{
    if (status) {
        printf("\nOther went online.\n");
    } else {
        printf("\nOther went offline.\n");
        unsigned int i;

        for (i = 0; i < NUM_FILE_SENDERS; ++i) {
            if (file_senders[i].file != 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;
            }

            if (file_recv[i].file != 0) {
                fclose(file_recv[i].file);
                file_recv[i].file = 0;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    uint8_t ipv6enabled = 1; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    /* with optional --ipvx, now it can be 1-4 arguments... */
    if ((argc != argvoffset + 3) && (argc != argvoffset + 5)) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key (of the DHT bootstrap node) folder (to sync)\n", argv[0]);
        exit(0);
    }

    Tox *tox = tox_new(0, 0);
    tox_callback_file_recv_chunk(tox, write_file);
    tox_callback_file_recv_control(tox, file_print_control);
    tox_callback_file_recv(tox, file_request_accept);
    tox_callback_file_chunk_request(tox, tox_file_chunk_request);
    tox_callback_friend_connection_status(tox, print_online);

    uint16_t port = atoi(argv[argvoffset + 2]);
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = tox_bootstrap(tox, argv[argvoffset + 1], port, binary_string, 0);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        exit(1);
    }

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, address);
    uint32_t i;

    for (i = 0; i < TOX_ADDRESS_SIZE; i++) {
        printf("%02X", address[i]);
    }

    char temp_id[128];
    printf("\nEnter the address of the other id you want to sync with (38 bytes HEX format):\n");

    if (scanf("%s", temp_id) != 1) {
        return 1;
    }

    uint8_t *bin_id = hex_string_to_bin(temp_id);
    uint32_t num = tox_friend_add(tox, bin_id, (const uint8_t *)"Install Gentoo", sizeof("Install Gentoo"), 0);
    free(bin_id);

    if (num == UINT32_MAX) {
        printf("\nSomething went wrong when adding friend.\n");
        return 1;
    }

    memcpy(path, argv[argvoffset + 4], strlen(argv[argvoffset + 4]));
    DIR           *d;
    struct dirent *dir;
    uint8_t notconnected = 1;

    while (1) {
        if (tox_self_get_connection_status(tox) && notconnected) {
            printf("\nDHT connected.\n");
            notconnected = 0;
        }

        if (not_sending() && tox_friend_get_connection_status(tox, num, 0)) {
            d = opendir(path);

            if (d) {
                while ((dir = readdir(d)) != NULL) {
                    if (dir->d_type == DT_REG) {
                        char fullpath[1024];

                        if (path[strlen(path) - 1] == '/') {
                            sprintf(fullpath, "%s%s", path, dir->d_name);
                        } else {
                            sprintf(fullpath, "%s/%s", path, dir->d_name);
                        }

                        add_filesender(tox, num, fullpath);
                    }
                }

                closedir(d);
            } else {
                printf("\nFailed to open directory.\n");
                return 1;
            }
        }

        tox_iterate(tox, NULL);
        c_sleep(1);
    }
}
