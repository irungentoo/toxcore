LINK= -lsodium -lavformat -lavcodec -lavdevice -lswscale -lavutil -lm -lpthread `sdl-config --cflags` `sdl-config --libs` -lopenal
all: AV_codec test_video
AV_codec:
	gcc -g -O0 -c AV_codec.c $(LINK) -o AV_codec.o

test_video:
	gcc -g -O0 test_video.c AV_codec.o test_helper.c libtoxrtp.a libtoxcore.a $(LINK) -o test_video
test_regular:
	gcc -g -O0 test_regular.c test_helper.c libtoxrtp.a libtoxcore.a -lsodium -o test_regular
	
test_bidirect:
	gcc -g -O0 test_bidirect.c test_helper.c libtoxrtp.a libtoxcore.a -lsodium -o test_bidirect

clean:
	rm AV_codec.o test_video
