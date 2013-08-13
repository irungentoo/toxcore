#include "../core/timer.h"
#include <stdio.h>

#ifdef WINDOWS
#include <windows.h>
#else 
#include <unistd.h>
#endif

void mssleep(int ms)
{
#ifdef WINDOWS
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

int callback(timer* t, void* arg){
    printf("%s\n", (char*)arg);
    return 1;
}

int repeating(timer* t, void *arg) {
    printf("%s\n", (char*)arg);
    timer_start(t, 3);
    return 0;
}

extern void timer_debug_print();

int main(int argc, char** argv)
{
    timer_init();
    timer_debug_print();
    
    timer* t = new_timer();
    timer_setup(t, &callback, "Long setup method, 4 seconds");
    timer_start(t, 4);
    timer_debug_print();

    timer_single(&repeating, (void*)"This repeats every 3 seconds", 3);
    timer_debug_print();

    timer_single(&callback, "Short method, 4 seconds", 4);
    timer_debug_print();

    timer_single(&callback, "1 second", 1);
    timer_debug_print();

    timer_single(&callback, "15 seconds", 15);
    timer_debug_print();

    timer_single(&callback, "10 seconds", 10);
    timer_debug_print();
    
    timer_us(&callback, "100000us", 100000);
    timer_us(&callback, "13s", 13 * US_PER_SECOND);

    while (true) {
        timer_poll();
        mssleep(10);
    }

    return 0;
}
