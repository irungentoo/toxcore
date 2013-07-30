CC=gcc
FLAGS=-g -Wall -Wextra -std=c99 -c
LINK=-lcore -lsodium
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
	$(CC) $(FLAGS) tests/test_regular.c -o tests/test_regular.o
	$(CC) -o tests/test_regular $(CORE_STATIC) *.o tests/*.o 
	
#/usr/local/lib/libsodium.a /usr/local/lib/libsodium.so