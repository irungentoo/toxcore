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

#include <dirent.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NUM_FILE_SENDERS 256
typedef struct {
    FILE *file;
    uint16_t friendnum;
    uint8_t filenumber;
    uint8_t nextpiece[1400];
    uint16_t piecelength;
} File_t;
File_t file_senders[NUM_FILE_SENDERS];
File_t file_recv[NUM_FILE_SENDERS];
uint8_t numfilesenders;

void send_filesenders(Tox *m)
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        if (file_senders[i].file == 0)
            continue;

        while (1) {
            if (tox_file_send_data(m, file_senders[i].friendnum, file_senders[i].filenumber, file_senders[i].nextpiece,
                                   file_senders[i].piecelength) != 0)
                break;

            file_senders[i].piecelength = fread(file_senders[i].nextpiece, 1, tox_file_data_size(m, file_senders[i].friendnum),
                                                file_senders[i].file);

            if (file_senders[i].piecelength == 0) {
                fclose(file_senders[i].file);
                file_senders[i].file = 0;

                printf("[t] %u file transfer: %u completed %i\n", file_senders[i].friendnum, file_senders[i].filenumber,
                       tox_file_send_control(m, file_senders[i].friendnum, 0, file_senders[i].filenumber, TOX_FILECONTROL_FINISHED, 0, 0));
                break;
            }
        }
    }
}
int add_filesender(Tox *m, uint16_t friendnum, char *filename)
{
    FILE *tempfile = fopen(filename, "rb");

    if (tempfile == 0)
        return -1;

    fseek(tempfile, 0, SEEK_END);
    uint64_t filesize = ftell(tempfile);
    fseek(tempfile, 0, SEEK_SET);
    int filenum = tox_new_file_sender(m, friendnum, filesize, (uint8_t *)filename, strlen(filename) + 1);

    if (filenum == -1)
        return -1;

    file_senders[numfilesenders].file = tempfile;
    file_senders[numfilesenders].piecelength = fread(file_senders[numfilesenders].nextpiece, 1, tox_file_data_size(m,
            file_senders[numfilesenders].friendnum),
            file_senders[numfilesenders].file);
    file_senders[numfilesenders].friendnum = friendnum;
    file_senders[numfilesenders].filenumber = filenum;
    ++numfilesenders;
    return filenum;
}

void kill_filesender(Tox *m, uint8_t filenum)
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i)
        if (file_senders[i].file != 0 && file_senders[i].filenumber == filenum) {
            fclose(file_senders[i].file);
            file_senders[i].file = 0;
        }
}
int not_sending()
{
    uint32_t i;

    for (i = 0; i < NUM_FILE_SENDERS; ++i)
        if (file_senders[i].file != 0)
            return 0;

    return 1;
}

static char path[1024];

void file_request_accept(Tox *m, int friendnumber, uint8_t filenumber, uint64_t filesize, const uint8_t *filename,
                         uint16_t filename_length, void *userdata)
{
    char fullpath[1024];
    uint32_t i;
    uint16_t rm = 0;

    for (i = 0; i < strlen((char *)filename); ++i) {
        if (filename[i] == '/')
            rm = i;
    }

    if (path[strlen(path) - 1] == '/')
        sprintf(fullpath, "%s%s", path, filename + rm + 1);
    else
        sprintf(fullpath, "%s/%s", path, filename + rm + 1);

    FILE *tempfile = fopen(fullpath, "rb");

    if (tempfile != 0) {
        fclose(tempfile);
        tox_file_send_control(m, friendnumber, 1, filenumber, TOX_FILECONTROL_KILL, 0, 0);
        return;
    }

    file_recv[filenumber].file = fopen(fullpath, "wb");

    if (file_recv[filenumber].file == 0) {
        tox_file_send_control(m, friendnumber, 1, filenumber, TOX_FILECONTROL_KILL, 0, 0);
        return;
    }

    if (tox_file_send_control(m, friendnumber, 1, filenumber, TOX_FILECONTROL_ACCEPT, 0, 0) == 0) {
        printf("Accepted file transfer. (file: %s)\n", fullpath);
    }

}

void file_print_control(Tox *m, int friendnumber, uint8_t recieve_send, uint8_t filenumber, uint8_t control_type,
                        const uint8_t *data,
                        uint16_t length, void *userdata)
{
    if (recieve_send == 1 && (control_type == TOX_FILECONTROL_KILL || control_type == TOX_FILECONTROL_FINISHED)) {
        kill_filesender(m, filenumber);
        return;
    }

    if (recieve_send == 0 && (control_type == TOX_FILECONTROL_KILL || control_type == TOX_FILECONTROL_FINISHED)) {
        fclose(file_recv[filenumber].file);
        printf("File closed\n");
        file_recv[filenumber].file = 0;
        return;
    }
}

void write_file(Tox *m, int friendnumber, uint8_t filenumber, const uint8_t *data, uint16_t length, void *userdata)
{
    if (file_recv[filenumber].file != 0)
        if (fwrite(data, length, 1, file_recv[filenumber].file) != 1)
            printf("Error writing data\n");
}

void print_online(Tox *tox, int friendnumber, uint8_t status, void *userdata)
{
    if (status == 1)
        printf("\nOther went online.\n");
    else
        printf("\nOther went offline.\n");
}

int main(int argc, char *argv[])
{
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    /* with optional --ipvx, now it can be 1-4 arguments... */
    if ((argc != argvoffset + 3) && (argc != argvoffset + 5)) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key (of the DHT bootstrap node) folder (to sync)\n", argv[0]);
        exit(0);
    }

    Tox *tox = tox_new(ipv6enabled);
    tox_callback_file_data(tox, write_file, NULL);
    tox_callback_file_control(tox, file_print_control, NULL);
    tox_callback_file_send_request(tox, file_request_accept, NULL);
    tox_callback_connection_status(tox, print_online, NULL);

    uint16_t port = htons(atoi(argv[argvoffset + 2]));
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = tox_bootstrap_from_address(tox, argv[argvoffset + 1], ipv6enabled, port, binary_string);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        exit(1);
    }

    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox, address);
    uint32_t i;

    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        printf("%02X", address[i]);
    }

    char temp_id[128];
    printf("\nEnter the address of the other id you want to sync with (38 bytes HEX format):\n");

    if (scanf("%s", temp_id) != 1) {
        return 1;
    }

    uint8_t *bin_id = hex_string_to_bin(temp_id);
    int num = tox_add_friend(tox, bin_id, (uint8_t *)"Install Gentoo", sizeof("Install Gentoo"));
    free(bin_id);

    if (num < 0) {
        printf("\nSomething went wrong when adding friend.\n");
        return 1;
    }

    memcpy(path, argv[argvoffset + 4], strlen(argv[argvoffset + 4]));
    DIR           *d;
    struct dirent *dir;
    uint8_t notconnected = 1;

    while (1) {
        if (tox_isconnected(tox) && notconnected) {
            printf("\nDHT connected.\n");
            notconnected = 0;
        }

        if (not_sending() && tox_get_friend_connection_status(tox, num)) {
            d = opendir(path);

            if (d) {
                while ((dir = readdir(d)) != NULL) {
                    if (dir->d_type == DT_REG) {
                        char fullpath[1024];

                        if (path[strlen(path) - 1] == '/')
                            sprintf(fullpath, "%s%s", path, dir->d_name);
                        else
                            sprintf(fullpath, "%s/%s", path, dir->d_name);

                        add_filesender(tox, num, fullpath);
                    }
                }

                closedir(d);

            } else {
                printf("\nFailed to open directory.\n");
                return 1;
            }
        }

        send_filesenders(tox);
        tox_do(tox);
        c_sleep(1);
    }

    return 0;
}
