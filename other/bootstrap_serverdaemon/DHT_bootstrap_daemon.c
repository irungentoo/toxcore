/* DHT boostrap
*
* A simple DHT boostrap server for tox (daemon edition)
*/
    
#include <sys/types.h> /* pid_t */
#include <sys/stat.h> /* umask */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> /* POSIX things */
#include <errno.h>
    
#include "../../core/DHT.h"
#include "../../core/friend_requests.h"

    
/* Sleep function (x = milliseconds) */
#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif
    
#define PORT 33445
#define USERNAME getenv("USER")
#define PIDFILE "/home/%s/.bootstrap_server.pid" /* %s represents the unser's name */
    
int main(int argc, char *argv[]) {
    
    char pidfloc[512]; /* Location of the soon-to-be PID file */
    pid_t pid, sid; /* Process- and Session-ID */
    
    FILE *pidf; /* The PID file */
    
    /* Assemble PID file location an try to open the file */
    sprintf(pidfloc, PIDFILE, USERNAME);
    pidf = fopen(pidfloc, "w");
    
    /* Generate new keypair */
    new_keys();
    
    /* Public key */
    uint32_t i;
    
    printf("\nPublic Key: ");
    for(i = 0; i < 32; i++)
    {
        uint8_t ln, hn;
        ln = 0x0F & self_public_key[i];
        hn = 0xF0 & self_public_key[i];
        hn = hn >> 4;
        printf("%X%X", hn, ln);
    }
    printf("\n");
    
    /* initialize networking
    bind to ip 0.0.0.0:PORT */
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);
    
    /* If there's been an error, exit before forking off */
    if (errno != 0) {
        perror("Error");
        printf("Error(s) occured during start-up. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    
//    /* Assemble the location of the PID file */
//    sprintf(pidfloc, PIDFILE, USERNAME);
//    pidf = fopen(pidfloc, "w");
//    /* Check if we can actually open the file */
//    if(pidf == NULL) {
//        printf("Couldn't open PID-File %s for writing.\n", pidfloc);
//        exit(EXIT_FAILURE);
//    }
    
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        printf("Forking failed.\n");
        exit(EXIT_FAILURE);
    }
    
    /* If we got a good PID, then
    we can exit the parent process. */
    if (pid > 0) {
        printf("Forked successfully: %d\n", pid);
    
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
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    
    /* Main loop */
    while(1) {
        doDHT();
        while(receivepacket(&ip_port, data, &length) != -1) {
            DHT_handlepacket(data, length, ip_port);
            friendreq_handlepacket(data, length, ip_port);
        }
        c_sleep(1);
    }
    
    shutdown_networking();
    exit(EXIT_SUCCESS);
}

