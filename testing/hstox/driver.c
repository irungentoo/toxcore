#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "driver.h"
#include "errors.h"
#include "methods.h"
#include "util.h"

#include <sodium.h>

static void handle_interrupt(int signum)
{
    printf("Caught signal %d; exiting cleanly.\n", signum);
    exit(0);
}

static int protocol_error(msgpack_packer *pk, char const *fmt, ...)
{
    msgpack_pack_array(pk, 4); // 4 elements in the array
    msgpack_pack_uint8(pk, 1); // 1. type = response
    // 2. We don't know the msgid, because the packet we received is not a valid
    // msgpack-rpc packet.
    msgpack_pack_uint64(pk, 0);

    // 3. Error message.
    va_list ap;
    va_start(ap, fmt);
    int res = msgpack_pack_vstringf(pk, fmt, ap);
    va_end(ap);

    // 4. No success result.
    msgpack_pack_array(pk, 0);

    return res;
}

static bool type_check(msgpack_packer *pk, msgpack_object req, int index,
                       msgpack_object_type type)
{
    if (req.via.array.ptr[index].type != type) {
        protocol_error(pk, "element %d should be %s, but is %s", index, type_name(type),
                       type_name(req.via.array.ptr[index].type));
        return false;
    }

    return true;
}

static int write_sample_input(msgpack_object req)
{
    static unsigned int n;

    char               filename[256];
    msgpack_object_str name = req.via.array.ptr[2].via.str;
    snprintf(filename, sizeof filename - name.size, "test-inputs/%04u-", n++);

    assert(sizeof filename - strlen(filename) > name.size + 4);
    memcpy(filename + strlen(filename) + name.size, ".mp", 4);
    memcpy(filename + strlen(filename), name.ptr, name.size);

    int fd = open(filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

    if (fd < 0)
        // If we can't open the sample file, we just don't write it.
    {
        return E_OK;
    }

    check_return(E_WRITE, ftruncate(fd, 0));

    msgpack_sbuffer sbuf __attribute__((__cleanup__(msgpack_sbuffer_destroy)));
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_object(&pk, req);

    check_return(E_WRITE, write(fd, sbuf.data, sbuf.size));

    return E_OK;
}

static int handle_request(struct settings cfg, int write_fd, msgpack_object req)
{
    msgpack_sbuffer sbuf __attribute__((__cleanup__(msgpack_sbuffer_destroy))); /* buffer */
    msgpack_sbuffer_init(&sbuf); /* initialize buffer */

    msgpack_packer pk;                                      /* packer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    if (req.type != MSGPACK_OBJECT_ARRAY) {
        protocol_error(&pk, "expected array, but got %s", type_name(req.type));
    } else if (req.via.array.size != 4) {
        protocol_error(&pk, "array length should be 4, but is %d", req.via.array.size);
    } else if (type_check(&pk, req, 0, MSGPACK_OBJECT_POSITIVE_INTEGER) &&
               type_check(&pk, req, 1, MSGPACK_OBJECT_POSITIVE_INTEGER) &&
               type_check(&pk, req, 2, MSGPACK_OBJECT_STR) &&
               type_check(&pk, req, 3, MSGPACK_OBJECT_ARRAY)) {
        if (cfg.collect_samples) {
            propagate(write_sample_input(req));
        }

        uint64_t msgid = req.via.array.ptr[1].via.u64;
        msgpack_object_str name = req.via.array.ptr[2].via.str;
        msgpack_object_array args = req.via.array.ptr[3].via.array;

        msgpack_pack_array(&pk, 4);      // 4 elements in the array
        msgpack_pack_uint8(&pk, 1);      // 1. type = response
        msgpack_pack_uint64(&pk, msgid); // 2. msgid

        if (name.size == (sizeof "rpc.capabilities") - 1 &&
                memcmp(name.ptr, "rpc.capabilities", name.size) == 0) {
            // 3. Error.
            msgpack_pack_string(&pk, "Capabilities negiotiation not implemented");
            // 4. No result.
            msgpack_pack_nil(&pk);
        } else {
            // if error is null, this writes 3. no error, and 4. result
            char const *error =
                call_method(name, args, &pk);

            if (error) {
                if (cfg.debug) {
                    printf("Error '%s' in request: ", error);
                    msgpack_object_print(stdout, req);
                    printf("\n");
                }

                msgpack_pack_string(&pk, error);
                msgpack_pack_array(&pk, 0);
            }
        }
    }

    check_return(E_WRITE, write(write_fd, sbuf.data, sbuf.size));

    return E_OK;
}

int communicate(struct settings cfg, int read_fd, int write_fd)
{
    msgpack_unpacker unp __attribute__((__cleanup__(msgpack_unpacker_destroy)));
    msgpack_unpacker_init(&unp, 128);

    while (true) {
        char buf[64];
        int  size = check_return(E_READ, read(read_fd, buf, sizeof buf));

        if (size == 0) {
            break;
        }

        if (msgpack_unpacker_buffer_capacity(&unp) < size &&
                !msgpack_unpacker_reserve_buffer(&unp, size)) {
            return E_NOMEM;
        }

        memcpy(msgpack_unpacker_buffer(&unp), buf, size);
        msgpack_unpacker_buffer_consumed(&unp, size);

        msgpack_unpacked req __attribute__((__cleanup__(msgpack_unpacked_destroy)));
        msgpack_unpacked_init(&req);

        switch (msgpack_unpacker_next(&unp, &req)) {
            case MSGPACK_UNPACK_SUCCESS:
                propagate(handle_request(cfg, write_fd, req.data));
                break;

            case MSGPACK_UNPACK_EXTRA_BYTES:
                printf("EXTRA_BYTES\n");
                break;

            case MSGPACK_UNPACK_CONTINUE:
                break;

            case MSGPACK_UNPACK_PARSE_ERROR:
                return E_PARSE;

            case MSGPACK_UNPACK_NOMEM_ERROR:
                return E_NOMEM;
        }
    }

    return E_OK;
}

static int closep(int *fd)
{
    return close(*fd);
}

static int run_tests(struct settings cfg, int port)
{
    int listen_fd __attribute__((__cleanup__(closep))) = 0;
    listen_fd = check_return(E_SOCKET, socket(AF_INET, SOCK_STREAM, 0));
    check_return(E_SOCKET, setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int) {
        1
    }, sizeof(int)));

    struct sockaddr_in servaddr;
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port        = htons(port);

    check_return(E_BIND, bind(listen_fd, (struct sockaddr *)&servaddr, sizeof servaddr));
    check_return(E_LISTEN, listen(listen_fd, 10));

    while (true) {
        int comm_fd __attribute__((__cleanup__(closep))) = 0;
        comm_fd = check_return(E_ACCEPT, accept(listen_fd, NULL, NULL));
        propagate(communicate(cfg, comm_fd, comm_fd));
    }

    return E_OK;
}

uint32_t network_main(struct settings cfg, uint16_t port, unsigned int timeout)
{
    signal(SIGALRM, handle_interrupt);
    signal(SIGINT, handle_interrupt);
    check_return(E_SODIUM, sodium_init());

    // Kill the process after `timeout` seconds so we don't get lingering
    // processes bound to the test port when something goes wrong with a test run.
    alarm(timeout);

    int result = run_tests(cfg, port);

    if (result == E_OK) {
        return E_OK;
    }

    return result | (errno << 8);
}
