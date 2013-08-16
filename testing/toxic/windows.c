#include "friendlist.h"
#include "prompt.h"
#include "dhtstatus.h"
#include "windows.h"

extern char *DATA_FILE;
extern int store_data(Messenger *m, char *path);

/* Holds status of chat windows */
char WINDOW_STATUS[MAX_WINDOW_SLOTS];

static int w_num;
static ToxWindow windows[MAX_WINDOW_SLOTS];
static Messenger *m;
int active_window;

static ToxWindow *prompt;

/* CALLBACKS START */
void on_request(uint8_t *public_key, uint8_t *data, uint16_t length, void *userdata)
{
    int n = add_req(public_key);
    wprintw(prompt->window, "\nFriend request from:\n");

    int i;

    for (i = 0; i < KEY_SIZE_BYTES; ++i) {
        wprintw(prompt->window, "%02x", public_key[i] & 0xff);
    }

    wprintw(prompt->window, "\nWith the message: %s\n", data);
    wprintw(prompt->window, "\nUse \"accept %d\" to accept it.\n", n);

    for (i = 0; i < MAX_WINDOW_SLOTS; ++i) {
        if (windows[i].onFriendRequest != NULL)
            windows[i].onFriendRequest(&windows[i], public_key, data, length);
    }
}

void on_message(Messenger *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    int i;

    for (i = 0; i < MAX_WINDOW_SLOTS; ++i) {
        if (windows[i].onMessage != NULL)
            windows[i].onMessage(&windows[i], m, friendnumber, string, length);
    }
}

void on_action(Messenger *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    int i;

    for (i = 0; i < MAX_WINDOW_SLOTS; ++i) {
        if (windows[i].onAction != NULL)
            windows[i].onAction(&windows[i], m, friendnumber, string, length);
    }
}

void on_nickchange(Messenger *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    wprintw(prompt->window, "\n(nickchange) %d: %s\n", friendnumber, string);
    int i;

    for (i = 0; i < MAX_WINDOW_SLOTS; ++i) {
        if (windows[i].onNickChange != NULL)
            windows[i].onNickChange(&windows[i], friendnumber, string, length);
    }
}

void on_statuschange(Messenger *m, int friendnumber, uint8_t *string, uint16_t length, void *userdata)
{
    wprintw(prompt->window, "\n(statuschange) %d: %s\n", friendnumber, string);
    int i;

    for (i = 0; i < MAX_WINDOW_SLOTS; ++i) {
        if (windows[i].onStatusChange != NULL)
            windows[i].onStatusChange(&windows[i], friendnumber, string, length);
    }
}

void on_friendadded(Messenger *m, int friendnumber)
{
    friendlist_onFriendAdded(m, friendnumber);

    if (store_data(m, DATA_FILE) != 0) {
        wprintw(prompt->window, "\nCould not store Messenger data\n");
    }
}
/* CALLBACKS END */

int add_window(Messenger *m, ToxWindow w, int n)
{
    if (w_num >= TOXWINDOWS_MAX_NUM)
        return -1;

    if (LINES < 2)
        return -1;

    w.window = newwin(LINES - 2, COLS, 0, 0);

    if (w.window == NULL)
        return -1;

    windows[n] = w;
    w.onInit(&w, m);
    w_num++;
    active_window = n;
    return n;
}

/* Deletes window w and cleans up */
void del_window(ToxWindow *w, int f_num)
{
    active_window = 0; // Go to prompt screen
    delwin(w->window);
    int i;

    for (i = N_DEFAULT_WINS; i < MAX_WINDOW_SLOTS; ++i) {
        if (WINDOW_STATUS[i] == f_num) {
            WINDOW_STATUS[i] = -1;
            disable_chatwin(f_num);
            break;
        }
    }

    clear();
    refresh();
}

/* Shows next window when tab or back-tab is pressed */
void set_active_window(int ch)
{
    int f_inf = 0;
    int max = MAX_WINDOW_SLOTS - 1;

    if (ch == '\t') {
        int i = (active_window + 1) % max;

        while (true) {
            if (WINDOW_STATUS[i] != -1) {
                active_window = i;
                return;
            }

            i = (i  + 1) % max;

            if (f_inf++ > max) {    // infinite loop check
                endwin();
                exit(2);
            }
        }
    } else {
        int i = active_window - 1;

        if (i < 0) i = max;

        while (true) {
            if (WINDOW_STATUS[i] != -1) {
                active_window = i;
                return;
            }

            if (--i < 0) i = max;

            if (f_inf++ > max) {
                endwin();
                exit(2);
            }
        }
    }
}

void init_window_status()
{
    /* Default window values decrement from -2 */
    int i;

    for (i = 0; i < N_DEFAULT_WINS; ++i)
        WINDOW_STATUS[i] = -(i + 2);

    int j;

    for (j = N_DEFAULT_WINS; j < MAX_WINDOW_SLOTS; j++)
        WINDOW_STATUS[j] = -1;
}

ToxWindow *init_windows()
{
    w_num = 0;
    int n_prompt = 0;
    int n_friendslist = 1;
    int n_dhtstatus = 2;

    if (add_window(m, new_prompt(on_friendadded), n_prompt) == -1
            || add_window(m, new_friendlist(WINDOW_STATUS), n_friendslist) == -1
            || add_window(m, new_dhtstatus(), n_dhtstatus) == -1) {
        fprintf(stderr, "add_window() failed.\n");
        endwin();
        exit(1);
    }

    active_window = n_prompt;
    prompt = &windows[n_prompt];
    return prompt;
}

static void draw_bar()
{
    static int odd = 0;
    int blinkrate = 30;

    attron(COLOR_PAIR(4));
    mvhline(LINES - 2, 0, '_', COLS);
    attroff(COLOR_PAIR(4));

    move(LINES - 1, 0);

    attron(COLOR_PAIR(4) | A_BOLD);
    printw(" TOXIC " TOXICVER "|");
    attroff(COLOR_PAIR(4) | A_BOLD);

    int i;

    for (i = 0; i < (MAX_WINDOW_SLOTS); ++i) {
        if (WINDOW_STATUS[i] != -1) {
            if (i == active_window)
                attron(A_BOLD);

            odd = (odd + 1) % blinkrate;

            if (windows[i].blink && (odd < (blinkrate / 2)))
                attron(COLOR_PAIR(3));

            printw(" %s", windows[i].title);

            if (windows[i].blink && (odd < (blinkrate / 2)))
                attroff(COLOR_PAIR(3));

            if (i == active_window) {
                attroff(A_BOLD);
            }
        }
    }

    refresh();
}

void prepare_window(WINDOW *w)
{
    mvwin(w, 0, 0);
    wresize(w, LINES - 2, COLS);
}

void draw_active_window(Messenger *m)
{

    ToxWindow *a = &windows[active_window];
    prepare_window(a->window);
    a->blink = false;
    draw_bar();
    a->onDraw(a);

    /* Handle input */
    int ch = getch();

    if (ch == '\t' || ch == KEY_BTAB)
        set_active_window(ch);
    else if (ch != ERR)
        a->onKey(a, m, ch);
}
