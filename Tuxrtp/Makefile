CC=gcc
FLAGS=-g -Wall -Wextra -std=c99 -c
LINK= -lsodium -lavformat -lavcodec -lavdevice -lswscale -lavutil -lm -lpthread `sdl-config --cflags` `sdl-config --libs`
LDIR=-L../core

#you may want to edit this for your liking
CORE_STATIC=../core/*.o

all: handler message rtp_impl test_helper

handler:	
	$(CC) $(FLAGS) handler.c -o handler.o

message:
	$(CC) $(FLAGS) rtp_message.c -o rtp_message.o
	
rtp_impl:
	$(CC) $(FLAGS) rtp_impl.c -o rtp_impl.o
	
test_helper:
	$(CC) $(FLAGS) tests/test_helper.c -o tests/test_helper.o

test_regular:
	$(CC) $(LINK) $(FLAGS) tests/test_regular.c -o tests/test_regular.o
	$(CC) -std=c99 $(LINK) -o tests/test_regular $(CORE_STATIC) *.o  ../core/helper.c tests/*.o 
	
test_video:
	$(CC) -std=c99 $(LINK) -o tests/test_video $(CORE_STATIC) *.o  ../core/helper.c tests/test_video.c tests/*.o 
	
#/usr/local/lib/libsodium.a /usr/local/lib/libsodium.so
