#include "dhtstatus.h"
#include "string.h"
#include "../../core/network.h"
#include "../../core/DHT.h"

typedef uint8_t ipbuf[3 * 4 + 3 + 1];
static int num_selected = 0;

static void printip(ipbuf buf, IP ip)
{
    sprintf((char *)buf, "%u.%u.%u.%u", ip.c[0], ip.c[1], ip.c[2], ip.c[3]);
}

static void dhtstatus_onKey(ToxWindow *self, Messenger *m, wint_t key)
{
    switch (key) {
        case KEY_UP:
        case 'k':
            if (--num_selected < 0)
                num_selected = CLIENT_ID_SIZE - 1;

            break;

        case KEY_DOWN:
        case 'j':
            num_selected = (num_selected + 1) % CLIENT_ID_SIZE;
            break;

        case '\n':
            break;

        default:
            break;
    }
}

static void dhtstatus_onDraw(ToxWindow *self, Messenger *m)
{
    Client_data   *close_clientlist = DHT_get_close_list(m->dht);
    curs_set(0);
    werase(self->window);

    uint64_t now = unix_time();
    uint32_t i, j;
    ipbuf ipbuf;
    wprintw(self->window,
            "\n%llu  ______________________ CLOSE LIST ________________________  ___ IP ADDR ___ _PRT_   LST   PNG    ____ SELF ____ _PRT_  LST\n\n",
            now);

    for (i = 0; i < 32; i++) { /*Number of nodes in closelist*/
        Client_data *client = close_clientlist + i;

        if (i == num_selected) wattron(self->window, COLOR_PAIR(3));

        wprintw(self->window, "[%02i]  ", i);
        uint16_t port = ntohs(client->ip_port.port);

        if (port) {
            for (j = 0; j < CLIENT_ID_SIZE; j++)
                wprintw(self->window, "%02hhx", client->client_id[j]);

            printip(ipbuf, client->ip_port.ip);
            wprintw(self->window, "  %15s %5u ", ipbuf, port);
            wprintw(self->window, "  %3llu ", now - client->timestamp);
            wprintw(self->window, "  %3llu ", now - client->last_pinged);

            port = ntohs(client->ret_ip_port.port);

            if (port) {
                printip(ipbuf, client->ret_ip_port.ip);
                wprintw(self->window, "  %15s %5u  %3llu", ipbuf, port, now - close_clientlist[i].ret_timestamp);
            }
        }

        wprintw(self->window, "\n");

        if (i == num_selected) wattroff(self->window, COLOR_PAIR(3));
    }

    wrefresh(self->window);
}

static void dhtstatus_onInit(ToxWindow *self, Messenger *m)
{

}

ToxWindow new_dhtstatus()
{
    ToxWindow ret;
    memset(&ret, 0, sizeof(ret));

    ret.onKey          = &dhtstatus_onKey;
    ret.onDraw         = &dhtstatus_onDraw;
    ret.onInit         = &dhtstatus_onInit;

    strcpy(ret.title, "[dht status]");
    return ret;
}
