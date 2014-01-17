/* DHT boostrap
 *
 * A simple DHT boostrap server for tox - daemon edition.
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

#include <sys/types.h> /* pid_t */
#include <sys/stat.h> /* umask */
#include <unistd.h> /* POSIX things */
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <arpa/inet.h> /* htons() */
#include <string.h> /* strcpy() */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../../toxcore/DHT.h"
#include "../../toxcore/friend_requests.h"

#define DEFAULT_PORT 33445
#define DEFAULT_PID_FILE "bootstrap_server.pid"
#define DEFAULT_KEYS_FILE "bootstrap_server.keys"

/* Server info struct */
struct server_info_s {
    int valid;
    IP_Port conn;
    uint8_t bs_pk[32];
};

/* This is the struct configure_server() uses to return its data to */
struct server_conf_s {
    int err;
    int port;
    char pid_file[512];
    char keys_file[512];
    struct server_info_s info[32];
};

int b16_to_key(char b16_string[], uint8_t *bs_pubkey)
{

    int i;
    unsigned int num1 = 0, num2 = 0;

    for (i = 0; i < 32; ++i) {
        sscanf(&b16_string[i * 2], "%1X", &num1);
        sscanf(&b16_string[i * 2 + 1], "%1X", &num2);
        num1 = num1 << 4;
        bs_pubkey[i] = bs_pubkey[i] | num1;
        bs_pubkey[i] = bs_pubkey[i] | num2;
    }

    return 0;
}

/*
  resolve_addr():
    address should represent IPv4 or a hostname with a record

    returns a data in network byte order that can be used to set IP.i or IP_Port.ip.i
    returns 0 on failure

    TODO: Fix ipv6 support
*/

uint32_t resolve_addr(const char *address)
{
    struct addrinfo *server = NULL;
    struct addrinfo  hints;
    int              rc;
    uint32_t         addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;    // IPv4 only right now.
    hints.ai_socktype = SOCK_DGRAM; // Type of socket Tox uses.

    rc = getaddrinfo(address, "echo", &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    // IPv4 records only..
    if (server->ai_family != AF_INET) {
        freeaddrinfo(server);
        return 0;
    }


    addr = ((struct sockaddr_in *)server->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(server);
    return addr;
}

/* This function connects to all specified servers
and connect to them.
returns 1 if the connection to the DHT is up
returns -1 if all attempts failed
*/
int connect_to_servers(DHT *dht, struct server_info_s *info)
{
    int i;
    int c;

    for (i = 0; i < 32; ++i) {
        if (info[i].valid) {
            /* Actual bootstrapping code goes here */
            //puts("Calling DHT_bootstrap");
            DHT_bootstrap(dht, info[i].conn, info[i].bs_pk);
        }
    }

    /* Check if we're connected to the DHT */
    for (c = 0; c != 100; ++c) {
        usleep(10000);

        if (DHT_isconnected(dht)) {
            //puts("Connected");
            return 1;
            break;
        }

        if (DHT_isconnected(dht) == 0 && c == 99) {
            //puts("Not connected");
            return -1;
            break;
        }

        do_DHT(dht);

        networking_poll(dht->c->lossless_udp->net);
    }

    /* This probably never happens */
    return 0;
}

void manage_keys(DHT *dht, char *keys_file)
{
    const uint32_t KEYS_SIZE = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint8_t keys[KEYS_SIZE];
    struct stat existence;
    FILE *keysf;

    /* Check if file exits, proceed to open and load keys */
    if (stat(keys_file, &existence) >= 0) {
        keysf = fopen(keys_file, "r");
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keysf);

        if (read_size != KEYS_SIZE) {
            printf("Error while reading the key file\nExiting.\n");
            exit(1);
        } else {
            printf("Keys loaded successfully\n");
        }

        load_keys(dht->c, keys);

    } else {
        /* Otherwise save new keys */
        /* Silly work-around to ignore any errors coming from new_keys() */
        new_keys(dht->c);
        save_keys(dht->c, keys);
        keysf = fopen(keys_file, "w");

        if (fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keysf) != KEYS_SIZE) {
            printf("Error while writing the key file.\nExiting.\n");
            exit(1);
        } else {
            printf("Keys saved successfully\n");
        }
    }

    fclose(keysf);
}

/* This reads the configuration file, and returns a struct server_conf_s with:
 *an error number:
    *-1 = file wasn't read, for whatever reason
    *-2 = no bootstrap servers found
 *the port
 *the location of the keys file
 *the location of the PID file
 *the list of bootstrap servers
*/
struct server_conf_s configure_server(char *cfg_file)
{
    config_t cfg;
    config_setting_t *server_list;

    /* This one will be strcpy'd into the pid_file array in server_conf */
    const char *pid_file_tmp;
    const char *keys_file_tmp;

    /* Remote bootstrap server variables */
    int bs_port;
    const char *bs_ip;
    const char *bs_pk;

    /* The big struct */
    static struct server_conf_s server_conf;

    /* Set both to their default values. If there's an error
    with opening/reading the config file, we return right away */
    server_conf.port = DEFAULT_PORT;
    strcpy(server_conf.pid_file, DEFAULT_PID_FILE);
    strcpy(server_conf.keys_file, DEFAULT_KEYS_FILE);

    config_init(&cfg);

    /* Read the file. If there is an error, report it and exit. */
    if (! config_read_file(&cfg, cfg_file)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        server_conf.err = -1;
        return server_conf;
    }

    /* Get the port to listen on */
    if (config_lookup_int(&cfg, "port", &server_conf.port)) {
        //printf("Port: %d\n", port);
    } else {
        fprintf(stderr, "No 'port' setting in configuration file.\n");
    }

    /* Get PID file location */
    if (config_lookup_string(&cfg, "pid_file", &pid_file_tmp)) {
        //printf("PID file: %s\n", pid_file_tmp);
        strcpy(server_conf.pid_file, pid_file_tmp);
    } else {
        fprintf(stderr, "No 'pid_file' setting in configuration file.\n");
    }

    /* Get keys file location */
    if (config_lookup_string(&cfg, "keys_file", &keys_file_tmp)) {
        //printf("Keys file: %s\n", keys_file_tmp);
        strcpy(server_conf.keys_file, keys_file_tmp);
    } else {
        fprintf(stderr, "No 'keys_file' setting in configuration file.\n");
    }

    /* Get all the servers in the list */
    server_list = config_lookup(&cfg, "bootstrap_servers");

    if (server_list != NULL) {
        int count = config_setting_length(server_list);
        int i;

        char tmp_ip[30]; /* IP */
        char tmp_pk[64]; /* bs_pk */

        for (i = 0; i < count; ++i) {
            config_setting_t *server = config_setting_get_elem(server_list, i);
            /* Get a pointer on the key array */
            uint8_t *bs_pk_p = server_conf.info[i].bs_pk;

            /* Only output the record if all of the expected fields are present. */
            if (!(config_setting_lookup_string(server, "ip", &bs_ip)
                    && config_setting_lookup_int(server, "port", &bs_port)
                    && config_setting_lookup_string(server, "bs_pk", &bs_pk)))
                continue;

            /* Converting all that stuff into usable formats and storing
            it away in the server_info struct */
            server_conf.info[i].valid = 1;

            if (resolve_addr(strcpy(tmp_ip, bs_ip)) == 0) {
                server_conf.info[i].valid = 0;
                printf("bootstrap_server %d: Invalid IP.\n", i);
            }

            if (strlen(bs_pk) != 64) {
                server_conf.info[i].valid = 0;
                printf("bootstrap_server %d: Invalid public key.\n", i);
            }

            if (!bs_port) {
                server_conf.info[i].valid = 0;
                printf("bootstrap_server %d: Invalid port.\n", i);
            }

            server_conf.info[i].conn.ip.family = AF_INET;
            server_conf.info[i].conn.ip.ip4.uint32 = resolve_addr(strcpy(tmp_ip, bs_ip));
            server_conf.info[i].conn.port = htons(bs_port);
            b16_to_key(strcpy(tmp_pk, bs_pk), bs_pk_p);
        }

        /* Check if at least one server entry is valid */
        for (i = 0; i < 32; ++i) {
            if (server_conf.info[i].valid)
                break;
            else
                server_conf.err = -2;
        }

    } else {
        server_conf.err = -2;
    }

    config_destroy(&cfg);
    return server_conf;
}

int main(int argc, char *argv[])
{

    pid_t pid, sid; /* Process- and Session-ID */
    struct server_conf_s server_conf;

    FILE *pidf; /* The PID file */

    if (argc < 2) {
        printf("Please specify a configuration file.\n");
        exit(EXIT_FAILURE);
    }

    server_conf = configure_server(argv[1]);

    /* Initialize networking
    bind to ip 0.0.0.0:PORT */
    IP ip;
    ip_init(&ip, 0);
    DHT *dht = new_DHT(new_net_crypto(new_networking(ip, server_conf.port)));
    Onion *onion = new_onion(dht);
    Onion_Announce *onion_a = new_onion_announce(dht);

    if (!(onion && onion_a)) {
        printf("Something failed to initialize.\n");
        exit(1);
    }
    /* Read the config file */
    printf("PID file: %s\n", server_conf.pid_file);
    printf("Key file: %s\n", server_conf.keys_file);

    if (server_conf.err == -1)
        printf("Config file not read.\n");

    if (server_conf.err == -2)
        printf("No valid servers in list.\n");

    /* Open PID file for writing - if an error happens,
    it will be caught down the line */
    pidf = fopen(server_conf.pid_file, "w");

    /* Manage the keys */
    /* for now, just ignore any errors after this call. */
    int tmperr = errno;
    manage_keys(dht, server_conf.keys_file);
    errno = tmperr;

    /* We want our DHT public key to be the same as our internal one since this is a bootstrap server */
    memcpy(dht->self_public_key, dht->c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(dht->self_secret_key, dht->c->self_secret_key, crypto_box_SECRETKEYBYTES);

    /* Public key */
    int i;
    printf("\nPublic Key: ");

    for (i = 0; i < 32; ++i) {
        uint8_t ln, hn;
        ln = 0x0F & dht->c->self_public_key[i];
        hn = 0xF0 & dht->c->self_public_key[i];
        hn = hn >> 4;
        printf("%X%X", hn, ln);
    }

    printf("\n");

    /* Bootstrap the DHT
    This one throws odd errors, too. Ignore. I assume they come
    from somewhere in the core. */
    tmperr = errno;
    connect_to_servers(dht, server_conf.info);
    errno = tmperr;

    if (!DHT_isconnected(dht)) {
        puts("Could not establish DHT connection. Check server settings.\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Connected to DHT successfully.\n");
    }

    /* If there's been an error, exit before forking off */
    if (errno != 0) {
        perror("Error");
        printf("Error(s) occured during start-up. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    /* Things that make the daemon work come past here.
    There should be nothing here but the daemon code and
    the main loop. */

    /* Fork off from the parent process */
    pid = fork();

    if (pid < 0) {
        printf("Forking failed.\n");
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
    we can exit the parent process. */
    if (pid > 0) {
        printf("Forked successfully: %d.\n", pid);

        /* Write the PID file */
        fprintf(pidf, "%d\n", pid);
        fclose(pidf);

        /* Exit parent */
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();

    if (sid < 0) {
        printf("SID creation failure.\n");
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Go quiet */
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    close(STDERR_FILENO);

    while (1) {
        do_DHT(dht);

        networking_poll(dht->c->lossless_udp->net);
        usleep(10000);
    }

    //shutdown_networking();
    exit(EXIT_SUCCESS);
}
