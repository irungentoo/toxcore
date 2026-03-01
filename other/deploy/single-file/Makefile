TARGETS = libtoxcore.a libtoxcore-minimal.a

all: $(TARGETS)

libtoxcore.o: $(wildcard toxcore-*av.c)
	$(CC) -c -o $@ $< \
		-O2 \
		-Wno-discarded-qualifiers \
		-fPIC \
		-Wl,-Bstatic \
		$(shell pkg-config --cflags --libs libsodium) \
		-Wl,-Bdynamic \
		$(shell pkg-config --cflags --libs opus vpx) \
		-pthread

libtoxcore-minimal.o: $(wildcard toxcore-*core.c)
	$(CC) -c -o $@ $< \
		-O2 \
		-Wno-discarded-qualifiers \
		-fPIC \
		-Wl,-Bstatic \
		$(shell pkg-config --cflags --libs libsodium) \
		-pthread

%.a: %.o
	$(AR) rcs $@ $^
